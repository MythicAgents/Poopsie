import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import std/[json, strformat, strutils]
import token_manager

when defined(windows):
  import winim/lean
  
  const
    TOKEN_QUERY = 0x0008
    TokenPrivileges = 3
    SE_PRIVILEGE_ENABLED = 0x00000002
    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
    
  type
    LUID_GETPRIVS = object
      LowPart: DWORD
      HighPart: LONG
    
    LUID_AND_ATTRIBUTES_GETPRIVS = object
      Luid: LUID_GETPRIVS
      Attributes: DWORD
    
    TOKEN_PRIVILEGES_GETPRIVS = object
      PrivilegeCount: DWORD
      Privileges: array[1, LUID_AND_ATTRIBUTES_GETPRIVS]
  
  proc GetTokenInformation(TokenHandle: HANDLE, TokenInformationClass: DWORD,
                          TokenInformation: pointer, TokenInformationLength: DWORD,
                          ReturnLength: ptr DWORD): WINBOOL 
    {.importc, dynlib: obf("advapi32.dll"), stdcall.}
  
  proc LookupPrivilegeNameA(lpSystemName: LPCSTR, lpLuid: ptr LUID_GETPRIVS,
                           lpName: LPSTR, cchName: ptr DWORD): WINBOOL 
    {.importc, dynlib: obf("advapi32.dll"), stdcall.}

proc getprivs*(taskId: string, params: JsonNode): JsonNode =
  ## Get the privileges of the current process
  when defined(windows):
    try:
      debug "[DEBUG] GetPrivs: Getting current user privileges"
      
      # Get current username and hostname for output
      let username = getCurrentUsername()
      var output = obf("Privileges for '") & username & "'\n\n"
      
      debug &"[DEBUG] GetPrivs: Current user: {username}"
      
      # Get handle to current process token
      var tokenHandle: HANDLE = 0
      if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr tokenHandle) == 0:
        return mythicError(taskId, obf("Failed to open token handle: ") & $GetLastError())
      
      debug "[DEBUG] GetPrivs: Opened process token"
      
      # Get the required size for token information
      var privLen: DWORD = 0
      discard GetTokenInformation(tokenHandle, TokenPrivileges, nil, 0, addr privLen)
      
      if privLen == 0:
        CloseHandle(tokenHandle)
        return mythicError(taskId, obf("Failed to get token information length: ") & $GetLastError())
      
      debug &"[DEBUG] GetPrivs: Token information size: {privLen}"
      
      # Allocate buffer and get the actual token information
      var privs = newSeq[byte](privLen)
      if GetTokenInformation(tokenHandle, TokenPrivileges, addr privs[0], privLen, addr privLen) == 0:
        CloseHandle(tokenHandle)
        return mythicError(taskId, obf("Failed to query privileges: ") & $GetLastError())
      
      debug "[DEBUG] GetPrivs: Retrieved token information"
      
      # Cast the buffer to TOKEN_PRIVILEGES structure
      let tokenPrivs = cast[ptr TOKEN_PRIVILEGES_GETPRIVS](addr privs[0])
      let count = tokenPrivs.PrivilegeCount
      
      debug &"[DEBUG] GetPrivs: Found {count} privileges"
      
      # Get pointer to the array of LUID_AND_ATTRIBUTES
      let luidsPtr = cast[ptr UncheckedArray[LUID_AND_ATTRIBUTES_GETPRIVS]](addr tokenPrivs.Privileges[0])
      
      # Iterate over each LUID and map it to a privilege name
      for i in 0..<count:
        var nameBuffer: array[512, char]
        var nameSize: DWORD = DWORD(nameBuffer.len)
        
        if LookupPrivilegeNameA(nil, addr luidsPtr[i].Luid, cast[LPSTR](addr nameBuffer[0]), addr nameSize) != 0:
          let privName = $cast[cstring](addr nameBuffer[0])
          
          # Check if privilege is enabled
          let attrs = luidsPtr[i].Attributes
          var status = ""
          if (attrs and SE_PRIVILEGE_ENABLED) != 0:
            status = obf(" (Enabled)")
          elif (attrs and SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0:
            status = obf(" (Default)")
          
          output.add(&"{privName}{status}\n")
          
          debug &"[DEBUG] GetPrivs: {privName}{status}"
      
      CloseHandle(tokenHandle)
      
      # Remove trailing newline
      if output.endsWith("\n"):
        output = output[0..^2]
      
      return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, obf("GetPrivs error: ") & e.msg)
  else:
    return mythicError(taskId, obf("getprivs command is only available on Windows"))