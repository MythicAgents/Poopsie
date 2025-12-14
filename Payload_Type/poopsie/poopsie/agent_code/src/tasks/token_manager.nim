## Token Manager - Stores and manages impersonation tokens
## Used by make_token, steal_token, and rev2self commands

when defined(windows):
  import winim/lean
  
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
else:
  # Unix placeholders (not needed but required for compilation)
  type HANDLE* = int
  
  var globalTokenHandle*: HANDLE = 0
  
  proc setTokenHandle*(handle: HANDLE) = discard
  proc getTokenHandle*(): HANDLE = 0
  proc clearTokenHandle*() = discard
