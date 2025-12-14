## Rev2Self - Revert token to the implant's primary token

import std/[json, strformat]
import ../config
import ../utils/mythic_responses
import token_manager

when defined(windows):
  import winim/lean
  import std/os
  
  proc rev2self*(taskId: string, params: JsonNode): JsonNode =
    ## Revert to the original process token
    let cfg = getConfig()
    
    try:
      if cfg.debug:
        echo "[DEBUG] rev2self: Reverting to self"
      
      # Revert to self
      if RevertToSelf() == 0:
        let errorCode = GetLastError()
        return mythicError(taskId, &"Failed to revert to self. Error code: {errorCode}")
      
      # Clear the stored token handle
      clearTokenHandle()
      
      # Get the current user after reverting
      let user = getEnv("USERNAME", "unknown")
      
      if cfg.debug:
        echo &"[DEBUG] Reverted to original identity: {user}"
      
      # Build response with callback data
      return mythicCallback(taskId, &"Reverted identity to self: {user}", %*{
        "impersonation_context": ""  # Empty string indicates no impersonation
      })
      
    except:
      let e = getCurrentException()
      return mythicError(taskId, &"rev2self error: {e.msg}")

else:
  # Unix placeholder
  proc rev2self*(taskId: string, params: JsonNode): JsonNode =
    return mythicError(taskId, "rev2self is only available on Windows")
