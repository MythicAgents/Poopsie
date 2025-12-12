from mythic_container.MythicCommandBase import *

class PtyArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="program",
                cli_name="Program",
                display_name="Program",
                type=ParameterType.ChooseOne,
                default_value="cmd.exe",
                choices=["cmd.exe", "powershell.exe", "bash", "sh", "zsh"],
                description="What program to spawn with a PTY",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=0)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception(
                "pty requires a program to run.\n\tUsage: {}".format(
                    PtyCommand.help_cmd
                )
            )
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split(" ", 1)
            self.add_arg("program", parts[0])
        pass


class PtyCommand(CommandBase):
    cmd = "pty"
    needs_admin = False
    help_cmd = "pty [program]"
    description = "This will spawn the program in a PTY so that it can be interacted with."
    version = 1
    author = "@haha150"
    supported_ui_features = ["task_response:interactive"]
    argument_class = PtyArguments
    attackmapping = ["T1106", "T1218", "T1553"]
    attributes = CommandAttributes(
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "-Program {}".format(
            taskData.args.get_arg("program")
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp