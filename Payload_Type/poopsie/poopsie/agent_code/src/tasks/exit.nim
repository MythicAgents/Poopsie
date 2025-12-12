import json

proc executeExit*(params: JsonNode): JsonNode =
  ## Execute the exit command - signals agent to terminate
  result = %*{
    "user_output": "Exiting agent...",
    "completed": true,
    "status": "completed"
  }
