import json
import ../utils/strenc

proc executeSleep*(params: JsonNode, sleepInterval: var int, jitter: var int): JsonNode =
  ## Execute the sleep command - updates agent sleep interval and jitter
  ## Returns error if interval parameter is missing
  
  if not params.hasKey(obf("interval")):
    return %*{
      obf("user_output"): obf("Error: interval parameter is required"),
      obf("completed"): true,
      obf("status"): "error"
    }
  
  let newInterval = params[obf("interval")].getInt()
  let newJitter = if params.hasKey(obf("jitter")): params[obf("jitter")].getInt() else: 0
  
  # Validate parameters - allow 0 seconds for immediate callback
  if newInterval < 0:
    return %*{
      obf("user_output"): obf("Error: interval must be 0 or greater"),
      obf("completed"): true,
      obf("status"): "error"
    }
  
  if newJitter < 0 or newJitter > 100:
    return %*{
      obf("user_output"): obf("Error: jitter must be between 0 and 100"),
      obf("completed"): true,
      obf("status"): "error"
    }
  
  # Update the sleep parameters
  sleepInterval = newInterval
  jitter = newJitter
  
  result = %*{
    obf("user_output"): obf("Set sleep interval to ") & $sleepInterval & obf(" seconds with jitter ") & $jitter & obf("%\n"),
    obf("completed"): true,
    obf("status"): obf("completed")
  }
