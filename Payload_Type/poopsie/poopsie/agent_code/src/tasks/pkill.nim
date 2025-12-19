import ../config
import ../utils/mythic_responses
import std/[json, strformat, strutils]

when defined(windows):
  import winim/lean
else:
  import std/osproc

proc pkill*(taskId: string, params: JsonNode): JsonNode =
  ## Kill a process by PID
  let cfg = getConfig()
  
  try:
    # Parse PID from parameters
    # Mythic sends this as a JSON string which parses to a JString
    let pidStr = $params
    
    let pid = try:
      pidStr.strip(chars = {'"', ' '}).parseInt()
    except:
      return mythicError(taskId, &"Invalid PID: {pidStr}")
    
    if cfg.debug:
      echo &"[DEBUG] pkill: Attempting to kill process with PID {pid}"
    
    when defined(windows):
      # Windows implementation using TerminateProcess
      const PROCESS_TERMINATE = 0x0001
      
      # Open process with terminate permission
      let hProcess = OpenProcess(PROCESS_TERMINATE, 0, DWORD(pid))
      
      if hProcess == 0:
        let errorCode = GetLastError()
        return mythicError(taskId, &"Failed to open process {pid}. Error code: {errorCode}. Make sure the process exists and you have sufficient permissions.")
      
      # Terminate the process
      let result = TerminateProcess(hProcess, 1)
      CloseHandle(hProcess)
      
      if result == 0:
        let errorCode = GetLastError()
        return mythicError(taskId, &"Failed to terminate process {pid}. Error code: {errorCode}")
      
      return mythicSuccess(taskId, &"Successfully terminated process {pid}")
    
    else:
      # Linux implementation using kill
      let (output, exitCode) = execCmdEx(&"kill -9 {pid}")
      
      if exitCode != 0:
        # Check if process exists
        let (checkOutput, checkCode) = execCmdEx(&"kill -0 {pid} 2>&1")
        if checkCode != 0:
          return mythicError(taskId, &"Process {pid} does not exist or you don't have permission to signal it")
        return mythicError(taskId, &"Failed to kill process {pid}: {output}")
      
      return mythicSuccess(taskId, &"Successfully killed process {pid}")
  
  except Exception as e:
    return mythicError(taskId, &"Error killing process: {e.msg}")
