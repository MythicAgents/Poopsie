from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import asyncio
import json


class GetSystemArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="method",
                cli_name="method",
                display_name="Elevation Method",
                type=ParameterType.ChooseOne,
                default_value="impersonate",
                choices=["impersonate"],
                description="Impersonate SYSTEM in the current callback by duplicating the winlogon.exe token.",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=1, group_name="Default"),
                ],
            ),
            CommandParameter(
                name="uuid",
                cli_name="Payload",
                display_name="Payload Template (Shellcode)",
                type=ParameterType.Payload,
                supported_agents=["poopsie"],
                supported_agent_build_parameters={"poopsie": {"output_type": "Shellcode"}},
                description="Provide a shellcode payload to spawn a new callback as SYSTEM.",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=1, group_name="Spawn"),
                ],
            ),
            CommandParameter(
                name="target",
                cli_name="target",
                display_name="Target Process",
                type=ParameterType.String,
                default_value="winlogon.exe",
                description="SYSTEM-owned process to inject into (e.g. winlogon.exe, lsass.exe, services.exe).",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=2, group_name="Spawn"),
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)


class GetSystemCommand(CommandBase):
    cmd = "getsystem"
    needs_admin = True
    help_cmd = "getsystem"
    description = "Elevate to SYSTEM by duplicating the winlogon.exe token. Default group impersonates SYSTEM in the current callback. Spawn group creates a new callback running as SYSTEM."
    version = 7
    author = "@its_a_feature_"
    argument_class = GetSystemArguments
    attackmapping = []
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        # If uuid is set, we're in the Spawn group - build the payload
        if taskData.args.get_arg("uuid") is not None:
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
                    NewDescription="{}'s getsystem spawned session from task {}".format(
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
                            response.DisplayParams = "Spawning new SYSTEM callback from '{}' into {}".format(
                                payload_search.Payloads[0].Description if payload_search.Success and len(payload_search.Payloads) > 0 else "unknown",
                                taskData.args.get_arg("target") or "winlogon.exe"
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
        else:
            response.DisplayParams = "Impersonating SYSTEM via winlogon token duplication"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp