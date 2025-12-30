import std/json
import strenc

proc mythicSuccess*(taskId: string, output: string): JsonNode =
  ## Create a successful task response for Mythic
  result = %*{
    obf("task_id"): taskId,
    obf("user_output"): output,
    obf("completed"): true,
    obf("status"): obf("success")
  }

proc mythicError*(taskId: string, msg: string): JsonNode =
  ## Create an error task response for Mythic
  result = %*{
    obf("task_id"): taskId,
    obf("user_output"): msg,
    obf("completed"): true,
    obf("status"): "error"
  }

proc mythicCallback*(taskId: string, output: string, callback: JsonNode): JsonNode =
  ## Create a successful task response with callback data for Mythic
  result = %*{
    obf("task_id"): taskId,
    obf("user_output"): output,
    obf("completed"): true,
    obf("status"): obf("success"),
    obf("callback"): callback
  }
