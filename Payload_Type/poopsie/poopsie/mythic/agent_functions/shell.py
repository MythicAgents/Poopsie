from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ShellArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="executable",
                cli_name="Executable",
                display_name="Executable",
                type=ParameterType.ChooseOne,
                choices=["default", "powershell.exe", "cmd.exe", "bash", "sh", "zsh"],
                default_value="default",
                description="Path to an executable to run.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=0)],
            ),
            CommandParameter(
                name="arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.ChooseOne,
                choices=["/S /c", "/C", "-c", "-e"],
                default_value="/S /c",
                description="Arguments to pass to the executable. Ignored if 'default' is selected as the executable.",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=1)
                ],
            ),
            CommandParameter(
                name="command",
                cli_name="Command",
                display_name="Command",
                type=ParameterType.String,
                description="Command to execute.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception(
                "shell requires at least one command-line parameter.\n\tUsage: {}".format(ShellCommand.help_cmd))
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception(
                "shell requires a JSON object as input.\n\tUsage: {}".format(ShellCommand.help_cmd))

class ShellCommand(CommandBase):
    cmd = "shell"
    attributes = CommandAttributes(
        dependencies=["run"],
        suggested_command=True,
        alias=True
    )
    needs_admin = False
    help_cmd = "shell [command] [arguments]"
    description = "Run a shell command which will translate to a process being spawned with command line: `cmd.exe /C [command]`"
    version = 2
    author = "@djhohnstein"
    argument_class = ShellArguments
    attackmapping = ["T1059"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            CommandName="run"
        )
        taskData.args.add_arg("executable", taskData.args.get_arg("executable"))
        if taskData.args.get_arg("executable") == "default":
            taskData.args.add_arg("arguments", taskData.args.get_arg("command"))
        else:
            taskData.args.add_arg("arguments", f"{taskData.args.get_arg('arguments')} {taskData.args.get_arg('command')}")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp