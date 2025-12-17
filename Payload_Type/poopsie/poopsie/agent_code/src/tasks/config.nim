import ../config
import ../utils/mythic_responses
import ../global_data
import ../tasks/token_manager
import std/[json, strformat]

proc config*(taskId: string, params: JsonNode): JsonNode =
  ## Display current agent configuration
  let cfg = getConfig()
  
  try:
    if cfg.debug:
      echo "[DEBUG] config: Getting configuration"
    
    var output = ""
    output &= "=== Agent Configuration ===\n"
    output &= &"UUID: {cfg.uuid}\n"
    output &= &"Callback Host: {cfg.callbackHost}:{cfg.callbackPort}\n"
    output &= &"Callback Interval: {cfg.callbackInterval}s\n"
    output &= &"Callback Jitter: {cfg.callbackJitter}%\n"
    output &= &"Kill Date: {cfg.killdate}\n"
    output &= &"Sleep Obfuscation: {cfg.sleepObfuscation}\n"
    
    when defined(windows):
      output &= "\n=== Process Injection Configuration ===\n"
      let (x64Path, x64Args) = getSpawntoX64()
      let (x86Path, x86Args) = getSpawntoX86()
      output &= &"spawnto_x64: {x64Path}\n"
      if x64Args.len > 0:
        output &= &"spawnto_x64_arguments: {x64Args}\n"
      output &= &"spawnto_x86: {x86Path}\n"
      if x86Args.len > 0:
        output &= &"spawnto_x86_arguments: {x86Args}\n"
      
      let ppid = getPpid()
      if ppid != 0:
        output &= &"PPID Spoofing: {ppid}\n"
      
      # Token information
      let tokenHandle = getTokenHandle()
      if tokenHandle != 0:
        output &= &"\n=== Token Information ===\n"
        output &= &"Impersonation Token: Active (Handle: {tokenHandle})\n"
        let username = getCurrentUsername()
        if username.len > 0:
          output &= &"Current User: {username}\n"
    
    return mythicSuccess(taskId, output)
    
  except Exception as e:
    return mythicError(taskId, &"config error: {e.msg}")
