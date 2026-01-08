import json
import ../utils/strenc

proc executeExit*(params: JsonNode): JsonNode =
  result = %*{
    obf("user_output"): obf("Exiting agent..."),
    obf("completed"): true,
    obf("status"): obf("completed")
  }
