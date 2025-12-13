import ../config
import ../utils/mythic_responses
import std/[json, strformat, os]

type
  CatArgs = object
    path: string

proc catFile*(taskId: string, params: string): JsonNode =
  let cfg = getConfig()
  
  # Parse arguments
  let args = parseJson(params).to(CatArgs)
  
  if cfg.debug:
    echo "[DEBUG] Reading file: ", args.path
  
  try:
    # Get current working directory
    let cwd = getCurrentDir()
    
    # Handle path resolution
    let fullPath = if args.path.isAbsolute():
      args.path
    else:
      cwd / args.path
    
    # Check if file exists
    if not fileExists(fullPath):
      return mythicError(taskId, &"File not found: {fullPath}")
    
    # Read file contents
    let content = readFile(fullPath)
    
    if cfg.debug:
      echo &"[DEBUG] Read {content.len} bytes from {fullPath}"
    
    # Create response with artifact
    var response = mythicSuccess(taskId, content)
    response["artifacts"] = %* [
      {
        "base_artifact": "FileOpen",
        "artifact": fullPath
      }
    ]
    
    return response
    
  except IOError as e:
    return mythicError(taskId, &"Failed to read file: {e.msg}")
  except Exception as e:
    return mythicError(taskId, &"Error: {e.msg}")
