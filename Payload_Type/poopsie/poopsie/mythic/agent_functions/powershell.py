from mythic_container.MythicCommandBase import *

class PowershellArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                cli_name="Command",
                display_name="Command",
                type=ParameterType.String,
                description="The PowerShell command to execute.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
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
                        required=False,
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
                        required=False,
                        ui_position=3
                    ),
                ]
            ),
            CommandParameter(
                name="scripts",
                cli_name="Scripts",
                display_name="Imported Scripts to Load",
                type=ParameterType.Array,
                default_value=[],
                description="Names of imported PowerShell scripts to load (from powershell_import). Leave empty to run without imported scripts. Use powershell_list to see available scripts.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=4
                    ),
                ]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("At least one command on the command line must be passed to PowerShell.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("command", self.command_line)
            self.add_arg("patch_amsi_arg", False)
            self.add_arg("block_etw_arg", False)
            self.add_arg("scripts", [])


class PowershellCommand(CommandBase):
    cmd = "powershell"
    needs_admin = False
    help_cmd = "powershell [command] [-BYPASSAMSI] [-BLOCKETW] [-Scripts script1.ps1,script2.ps1]"
    description = (
        "Run a PowerShell command by spawning powershell.exe (non-blocking). "
        "Optionally bypass AMSI and/or block ETW. "
        "Optionally specify imported scripts to load by name. "
        "Use powershell_list to see available imported scripts."
    )
    version = 3
    author = "@haha150"
    argument_class = PowershellArguments
    attackmapping = ["T1059.001"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        scripts = taskData.args.get_arg("scripts") or []
        if scripts:
            response.DisplayParams = "-Command {} -Scripts {}".format(
                taskData.args.get_arg("command"),
                ",".join(scripts)
            )
        else:
            response.DisplayParams = "-Command {}".format(
                taskData.args.get_arg("command")
            )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
