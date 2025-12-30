import ../utils/mythic_responses
import ../utils/debug
import ../utils/strenc
import std/[json, os, strformat, strutils]

type
  MvArgs = object
    source: string
    destination: string

proc mvFile*(taskId: string, params: string): JsonNode =
  # Parse arguments
  let args = parseJson(params).to(MvArgs)
  
  debug &"[DEBUG] Moving '{args.source}' to '{args.destination}'"
  
  try:
    # Check if source exists
    if not fileExists(args.source) and not dirExists(args.source):
      return mythicError(taskId, obf("Source path does not exist: ") & args.source)
    
    # Handle UNC paths and absolute paths for source
    let srcPath = if args.source.startsWith("\\\\") or isAbsolute(args.source):
      args.source
    else:
      getCurrentDir() / args.source
    
    let absSrcPath = if fileExists(srcPath) or dirExists(srcPath):
      normalizedPath(srcPath)
    else:
      return mythicError(taskId, obf("Source path does not exist: ") & srcPath)
    
    # Handle UNC paths and absolute paths for destination
    var destPath = if args.destination.startsWith("\\\\") or isAbsolute(args.destination):
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
    
    debug &"[DEBUG] Moved '{absSrcPath}' to '{normalizedDest}'"
    
    return mythicSuccess(taskId, obf("Moved '") & absSrcPath & obf("' to '") & normalizedDest & "'")
    
  except OSError as e:
    return mythicError(taskId, obf("Failed to move: ") & e.msg)
  except Exception as e:
    return mythicError(taskId, obf("Error: ") & e.msg)
