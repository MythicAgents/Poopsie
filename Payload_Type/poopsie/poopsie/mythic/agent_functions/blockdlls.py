from mythic_container.MythicCommandBase import *
import json


class BlockDllsArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="block",
                cli_name="EnableBlock",
                display_name="Block Non-Microsoft DLLs",
                type=ParameterType.Boolean,
                default_value=True,
                description="Block non-Microsoft signed DLLs from loading into sacrificial processes.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=1,
                        group_name="Default",
                    )
                ]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No action given.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            if self.command_line.lower().strip() in ["true", "1", "yes", "on"]:
                self.add_arg("block", True)
            elif self.command_line.lower().strip() in ["false", "0", "no", "off"]:
                self.add_arg("block", False)
            else:
                raise Exception("Invalid value. Use true/false.")


class BlockDllsCommand(CommandBase):
    cmd = "blockdlls"
    needs_admin = False
    help_cmd = "blockdlls -EnableBlock [true/false]"
    description = "Block non-Microsoft signed DLLs from loading into sacrificial processes. This prevents EDR hooking DLLs from being injected into child processes."
    version = 1
    author = "@haha150"
    argument_class = BlockDllsArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        block = taskData.args.get_arg("block")
        if block:
            response.DisplayParams = "Enabling DLL blocking"
        else:
            response.DisplayParams = "Disabling DLL blocking"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
