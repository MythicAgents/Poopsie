from mythic_container.MythicCommandBase import *

class ScshellArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="target",
                cli_name="Target",
                display_name="Target",
                type=ParameterType.String,
                description="Target to run the service on.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=0)],
            ),
            CommandParameter(
                name="service",
                cli_name="Service",
                display_name="Service",
                type=ParameterType.String,
                description="Service to run.",
                default_value="",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=1)
                ],
            ),
            CommandParameter(
                name="payload",
                cli_name="Payload",
                display_name="Payload",
                type=ParameterType.String,
                description="Payload to run as the service binary.",
                default_value="",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=2)
                ],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Invalid command line format.")


class ScshellCommand(CommandBase):
    cmd = "scshell"
    needs_admin = False
    help_cmd = "scshell [Target] [Service] [Payload]"
    description = "Execute a service on a target host using a specified payload binary."
    version = 1
    author = "@haha150"
    argument_class = ScshellArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "-Target {} -Service {} -Payload {}".format(
            taskData.args.get_arg("target"), taskData.args.get_arg("service"),
            taskData.args.get_arg("payload")
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp