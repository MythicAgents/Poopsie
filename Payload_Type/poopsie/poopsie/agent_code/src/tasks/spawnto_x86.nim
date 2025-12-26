import ../utils/mythic_responses
import ../utils/debug
import ../global_data
import std/[json, strformat]

proc spawnto_x86*(taskId: string, params: JsonNode): JsonNode =
  ## Set the default x86 binary for process injection
  when defined(windows):
    try:
      # Parse parameters
      let application = params["application"].getStr()
      let arguments = if params.hasKey("arguments"): params["arguments"].getStr() else: ""
      
      debug &"[DEBUG] spawnto_x86: Setting to {application} with args: {arguments}"
      
      # Set global spawnto values
      setSpawntoX86(application, arguments)
      
      let output = &"Set new spawnto_x86 to {application}"
      return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, &"spawnto_x86 error: {e.msg}")
  
  when defined(posix):
    return mythicError(taskId, "spawnto_x86 is only available on Windows")
