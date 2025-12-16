import ../config
import ../utils/mythic_responses
import std/[json, strformat]

when defined(windows):
  import winim/lean
  import std/widestrs

  proc whoamiWindows(): string =
    var hToken: HANDLE
    var dwSize: DWORD
    
    # Try to open thread token first (will succeed if impersonating)
    if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, addr hToken) == 0:
      # No thread token, try process token
      if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr hToken) == 0:
        return "Error: Failed to open process token"
    
    # Get the token user information size
    discard GetTokenInformation(hToken, 1, nil, 0, addr dwSize)  # TokenUser = 1
    
    # Allocate buffer for token user
    var pTokenUser = alloc(dwSize)
    if pTokenUser.isNil:
      CloseHandle(hToken)
      return "Error: Failed to allocate memory"
    
    # Get the token user information
    if GetTokenInformation(hToken, 1, pTokenUser, dwSize, addr dwSize) == 0:
      dealloc(pTokenUser)
      CloseHandle(hToken)
      return "Error: Failed to get token information"
    
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
      result = &"{domainName}\\{username}"
    else:
      result = "Error: Failed to lookup account SID"
    
    dealloc(pTokenUser)
    CloseHandle(hToken)

when not defined(windows):
  import std/[posix, osproc, strutils]
  
  proc whoamiUnix(): string =
    # Get UID and GID
    let uid = getuid()
    let gid = getgid()
    
    # Get username
    let username = try:
      let (output, _) = execCmdEx("whoami")
      output.strip()
    except:
      "unknown"
    
    # Get hostname
    let hostname = try:
      let (output, _) = execCmdEx("hostname")
      output.strip()
    except:
      "unknown"
    
    # Check if root
    let isRoot = uid == 0
    let privs = if isRoot: "root" else: "user"
    
    result = &"Username: {username}\nHostname: {hostname}\nUID: {uid}\nGID: {gid}\nPrivileges: {privs}"

proc whoami*(taskId: string, params: string): JsonNode =
  let cfg = getConfig()
  
  when defined(windows):
    let output = whoamiWindows()
  else:
    let output = whoamiUnix()
  
  if cfg.debug:
    echo "[DEBUG] whoami output: ", output
  
  return mythicSuccess(taskId, output)
