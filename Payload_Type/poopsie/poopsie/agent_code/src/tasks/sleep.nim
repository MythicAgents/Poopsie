import json

proc executeSleep*(params: JsonNode, sleepInterval: var int, jitter: var int): JsonNode =
  ## Execute the sleep command - updates agent sleep interval and jitter
  ## Returns error if interval parameter is missing
  
  if not params.hasKey("interval"):
    return %*{
      "user_output": "Error: interval parameter is required",
      "completed": true,
      "status": "error"
    }
  
  let newInterval = params["interval"].getInt()
  let newJitter = if params.hasKey("jitter"): params["jitter"].getInt() else: 0
  
  # Validate parameters - allow 0 seconds for immediate callback
  if newInterval < 0:
    return %*{
      "user_output": "Error: interval must be 0 or greater",
      "completed": true,
      "status": "error"
    }
  
  if newJitter < 0 or newJitter > 100:
    return %*{
      "user_output": "Error: jitter must be between 0 and 100",
      "completed": true,
      "status": "error"
    }
  
  # Update the sleep parameters
  sleepInterval = newInterval
  jitter = newJitter
  
  result = %*{
    "user_output": "Set new sleep interval to " & $newInterval & " second(s) with a jitter of " & $newJitter & "%",
    "completed": true,
    "status": "completed"
  }
