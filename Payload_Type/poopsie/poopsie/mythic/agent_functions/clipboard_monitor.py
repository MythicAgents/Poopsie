from mythic_container.MythicCommandBase import *

class ClipboardMonitorArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="duration",
                cli_name="Duration",
                display_name="Duration (in seconds)",
                type=ParameterType.Number,
                default_value=-1),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("clipboard_monitor [duration].")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            try:
                duration = int(self.command_line)
                if duration < 1 or duration > 3600:
                    raise Exception("Invalid duration given on command line.")
                self.add_arg("duration", duration)
            except:
                raise Exception("Invalid integer given to duration: {}".format(self.command_line))


class ClipboardMonitorCommand(CommandBase):
    cmd = "clipboard_monitor"
    needs_admin = False
    help_cmd = "clipboard_monitor [duration]"
    description = "Monitor clipboard changes for a specified duration."
    version = 1
    author = "@haha150"
    argument_class = ClipboardMonitorArguments
    attackmapping = []
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        duration = taskData.args.get_arg("duration")
        response.DisplayParams = "-Duration {}".format(duration)
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp