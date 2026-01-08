from mythic_container.MythicCommandBase import *
import json


class PkillArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="Process ID to kill",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        ui_position=1
                    )
                ]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("pkill requires a PID to kill.")
        try:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("pid", int(self.command_line), type=ParameterType.Number)
        except:
            raise Exception(f"Invalid integer value given for PID: {self.command_line}")


class PkillCommand(CommandBase):
    cmd = "pkill"
    needs_admin = False
    help_cmd = "pkill [pid]"
    description = "Kill a process by its Process ID (PID). On Windows, uses TerminateProcess. On Linux, uses kill -9."
    version = 1
    author = "@djhohnstein"
    argument_class = PkillArguments
    attackmapping = ["T1489"]
    supported_ui_features = ["process_browser:kill"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        taskData.args.set_manual_args(f"{taskData.args.get_arg('pid')}")
        response.DisplayParams = f"{taskData.args.get_arg('pid')}"
        return response
