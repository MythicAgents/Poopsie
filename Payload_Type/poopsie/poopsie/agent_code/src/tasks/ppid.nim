import ../utils/mythic_responses
import ../utils/debug
import ../global_data
import std/[json, strformat]

proc ppid*(taskId: string, params: JsonNode): JsonNode =
  ## Set the parent process ID for process spoofing
  when defined(windows):
    try:
      # Parse parameters
      let ppidValue = params["ppid"].getInt()
      
      if ppidValue < 0 or ppidValue mod 4 != 0:
        return mythicError(taskId, "Invalid PPID: must be non-negative and divisible by 4")
      
      debug &"[DEBUG] ppid: Setting to {ppidValue}"
      
      # Set global PPID value
      setPpid(uint32(ppidValue))
      
      let output = &"Set new parent process ID to {ppidValue}"
      return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, &"ppid error: {e.msg}")
  
  when defined(posix):
    return mythicError(taskId, "ppid is only available on Windows")
