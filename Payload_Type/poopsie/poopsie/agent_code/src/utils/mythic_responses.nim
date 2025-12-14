import std/json

proc mythicSuccess*(taskId: string, output: string): JsonNode =
  ## Create a successful task response for Mythic
  result = %*{
    "task_id": taskId,
    "user_output": output,
    "completed": true,
    "status": "success"
  }

proc mythicError*(taskId: string, msg: string): JsonNode =
  ## Create an error task response for Mythic
  result = %*{
    "task_id": taskId,
    "user_output": msg,
    "completed": true,
    "status": "error"
  }

proc mythicCallback*(taskId: string, output: string, callback: JsonNode): JsonNode =
  ## Create a successful task response with callback data for Mythic
  result = %*{
    "task_id": taskId,
    "user_output": output,
    "completed": true,
    "status": "success",
    "callback": callback
  }
