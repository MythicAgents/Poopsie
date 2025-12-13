from mythic_container.MythicCommandBase import *

class PowerpickArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                cli_name="Command",
                display_name="Command",
                type=ParameterType.String,
                description="Command to run.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="specific_payload",
                        ui_position=1
                    ),
                ]
            ),
            CommandParameter(
                name="patch_amsi_arg",
                cli_name="BYPASSAMSI",
                display_name="Bypass AMSI",
                type=ParameterType.Boolean,
                default_value=False,
                description="Bypass AMSI.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="specific_payload",
                        ui_position=2
                    ),
                ]
            ),
            CommandParameter(
                name="block_etw_arg",
                cli_name="BLOCKETW",
                display_name="Block ETW",
                type=ParameterType.Boolean,
                default_value=False,
                description="Block ETW.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="specific_payload",
                        ui_position=3
                    ),
                ]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("At least one command on the command line must be passed to Powerpick.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("command", self.command_line[0])
            self.add_arg("patch_amsi_arg", self.command_line[1])
            self.add_arg("block_etw_arg", self.command_line[2])


class PowerpickCommand(CommandBase):
    cmd = "powerpick"
    needs_admin = False
    help_cmd = "powerpick <BYPASSAMSI=0> <BLOCKETW=0> [command]"
    description = "Run a PowerShell command in a custom runspace."
    version = 2
    author = "@haha150"
    argument_class = PowerpickArguments
    attackmapping = ["T1059"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp