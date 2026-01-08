import ../utils/m_responses
import ../utils/debug
import ../global_data
import ../utils/strenc
import std/[json, strformat]

proc ppid*(taskId: string, params: JsonNode): JsonNode =
  ## Set the parent process ID for process spoofing
  when defined(windows):
    try:
      # Parse parameters
      let ppidValue = params[obf("ppid")].getInt()
      
      if ppidValue < 0 or ppidValue mod 4 != 0:
        return mythicError(taskId, obf("Invalid PPID: must be non-negative and divisible by 4"))
      
      debug &"[DEBUG] ppid: Setting to {ppidValue}"
      
      # Set global PPID value
      setPpid(uint32(ppidValue))
      
      let output = obf("Set new parent process ID to ") & $ppidValue
      return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, obf("ppid error: ") & e.msg)
  
  when defined(linux):
    return mythicError(taskId, obf("ppid is only available on Windows"))