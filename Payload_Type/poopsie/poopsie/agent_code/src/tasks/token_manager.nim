## Token Manager - Stores and manages impersonation tokens
## Used by make_token, steal_token, and rev2self commands

when defined(windows):
  import winim/lean
  import std/widestrs
  
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
    ## Tries thread token first, falls back to process token
    var hToken: HANDLE
    var dwSize: DWORD
    
    # Try to open thread token first (will succeed if impersonating)
    if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, addr hToken) == 0:
      # No thread token, try process token
      if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr hToken) == 0:
        return ""
    
    # Get the token user information size
    discard GetTokenInformation(hToken, 1, nil, 0, addr dwSize)  # TokenUser = 1
    
    if dwSize == 0:
      CloseHandle(hToken)
      return ""
    
    # Allocate buffer for token user
    var pTokenUser = alloc(dwSize)
    if pTokenUser.isNil:
      CloseHandle(hToken)
      return ""
    
    # Get the token user information
    if GetTokenInformation(hToken, 1, pTokenUser, dwSize, addr dwSize) == 0:
      dealloc(pTokenUser)
      CloseHandle(hToken)
      return ""
    
    # Extract the SID from TOKEN_USER structure
    let sid = cast[ptr PSID](pTokenUser)[]
    
    var nameSize: DWORD = 256
    var domainSize: DWORD = 256
    var name = newWideCString("", nameSize)
    var domain = newWideCString("", domainSize)
    var sidType: SID_NAME_USE
    
    # Lookup the account name from SID
    if LookupAccountSidW(nil, sid, cast[LPWSTR](name[0].addr), addr nameSize, 
                         cast[LPWSTR](domain[0].addr), addr domainSize, addr sidType) != 0:
      let username = $name
      let domainName = $domain
      if domainName.len > 0:
        result = domainName & "\\" & username
      else:
        result = username
    else:
      result = ""
    
    dealloc(pTokenUser)
    CloseHandle(hToken)
else:
  # Unix placeholders (not needed but required for compilation)
  type HANDLE* = int
  
  var globalTokenHandle*: HANDLE = 0
  
  proc setTokenHandle*(handle: HANDLE) = discard
  proc getTokenHandle*(): HANDLE = 0
  proc clearTokenHandle*() = discard
