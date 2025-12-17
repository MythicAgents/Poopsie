import ../config
import ../utils/mythic_responses
import ../global_data
import std/[json, strformat]

proc spawnto_x86*(taskId: string, params: JsonNode): JsonNode =
  ## Set the default x86 binary for process injection
  let cfg = getConfig()
  
  when defined(windows):
    try:
      # Parse parameters
      let application = params["application"].getStr()
      let arguments = if params.hasKey("arguments"): params["arguments"].getStr() else: ""
      
      if cfg.debug:
        echo &"[DEBUG] spawnto_x86: Setting to {application} with args: {arguments}"
      
      # Set global spawnto values
      setSpawntoX86(application, arguments)
      
      let output = &"Set new spawnto_x86 to {application}"
      return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, &"spawnto_x86 error: {e.msg}")
  
  when defined(posix):
    return mythicError(taskId, "spawnto_x86 is only available on Windows")
