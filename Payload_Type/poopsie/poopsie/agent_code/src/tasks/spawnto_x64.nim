import ../config
import ../utils/mythic_responses
import ../global_data
import std/[json, strformat]

proc spawnto_x64*(taskId: string, params: JsonNode): JsonNode =
  ## Set the default x64 binary for process injection
  let cfg = getConfig()
  
  when defined(windows):
    try:
      # Parse parameters
      let application = params["application"].getStr()
      let arguments = if params.hasKey("arguments"): params["arguments"].getStr() else: ""
      
      if cfg.debug:
        echo &"[DEBUG] spawnto_x64: Setting to {application} with args: {arguments}"
      
      # Set global spawnto values
      setSpawntoX64(application, arguments)
      
      let output = &"Set new spawnto_x64 to {application}"
      return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, &"spawnto_x64 error: {e.msg}")
  
  when defined(posix):
    return mythicError(taskId, "spawnto_x64 is only available on Windows")
