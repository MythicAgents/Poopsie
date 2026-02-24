import ../utils/m_responses
import ../utils/debug
import ../global_data
import ../utils/strenc
import std/[json]

proc blockdlls*(taskId: string, params: JsonNode): JsonNode =
  ## Toggle blocking of non-Microsoft signed DLLs in sacrificial processes
  when defined(windows):
    try:
      let blockValue = params[obf("block")].getBool()
      
      debug "[DEBUG] blockdlls: Setting to " & $blockValue
      
      setBlockDlls(blockValue)
      
      let output = if blockValue:
        obf("Enabled blocking of non-Microsoft signed DLLs in sacrificial processes")
      else:
        obf("Disabled blocking of non-Microsoft signed DLLs in sacrificial processes")
      
      return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, obf("blockdlls error: ") & e.msg)
  
  when defined(linux):
    return mythicError(taskId, obf("blockdlls is only available on Windows"))
