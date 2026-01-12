import ../config
import ../utils/m_responses
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
    output &= obf("Profile: ") & cfg.profile & "\n"
    
    # Profile-specific configuration
    case cfg.profile
    of "http":
      output &= obf("Callback Host: ") & cfg.callbackHost & ":" & $cfg.callbackPort & "\n"
      if cfg.postUri.len > 0:
        output &= obf("Post URI: ") & cfg.postUri & "\n"
      if cfg.userAgent.len > 0:
        output &= obf("User Agent: ") & cfg.userAgent & "\n"
      if cfg.headers.len > 0:
        output &= obf("Headers: ") & cfg.headers & "\n"
      if cfg.proxyHost.len > 0:
        output &= obf("Proxy: ") & cfg.proxyHost & ":" & cfg.proxyPort & "\n"
    of "httpx":
      if cfg.callbackDomains.len > 0:
        output &= obf("Callback Domains: ") & cfg.callbackDomains & "\n"
      if cfg.domainRotation.len > 0:
        output &= obf("Domain Rotation: ") & cfg.domainRotation & "\n"
      if cfg.failoverThreshold > 0:
        output &= obf("Failover Threshold: ") & $cfg.failoverThreshold & "\n"
      if cfg.postUri.len > 0:
        output &= obf("Post URI: ") & cfg.postUri & "\n"
      if cfg.headers.len > 0:
        output &= obf("Headers: ") & cfg.headers & "\n"
    of "websocket":
      output &= obf("Callback Host: ") & cfg.callbackHost & ":" & $cfg.callbackPort & "\n"
      if cfg.endpointReplace.len > 0:
        output &= obf("Endpoint: ") & cfg.endpointReplace & "\n"
      if cfg.userAgent.len > 0:
        output &= obf("User Agent: ") & cfg.userAgent & "\n"
    of "dns":
      if cfg.dnsServer.len > 0:
        output &= obf("DNS Server: ") & cfg.dnsServer & "\n"
      if cfg.domains.len > 0:
        output &= obf("Domains: ") & cfg.domains & "\n"
      if cfg.recordType.len > 0:
        output &= obf("Record Type: ") & cfg.recordType & "\n"
      if cfg.domainRotation.len > 0:
        output &= obf("Domain Rotation: ") & cfg.domainRotation & "\n"
      if cfg.maxQueryLength > 0:
        output &= obf("Max Query Length: ") & $cfg.maxQueryLength & "\n"
      if cfg.maxSubdomainLength > 0:
        output &= obf("Max Subdomain Length: ") & $cfg.maxSubdomainLength & "\n"
    of "tcp":
      output &= obf("Listen Port: ") & $cfg.callbackPort & "\n"
    else:
      output &= obf("Callback Host: ") & cfg.callbackHost & ":" & $cfg.callbackPort & "\n"
    
    # Sleep values from config (compile-time)
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
