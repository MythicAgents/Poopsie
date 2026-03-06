from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class DeregisterFileArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="Action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["list", "remove", "clear"],
                default_value="list",
                description="Action to perform on the file cache.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="Default", ui_position=1
                    )
                ],
            ),
            CommandParameter(
                name="name",
                cli_name="Name",
                display_name="Cache Name",
                type=ParameterType.String,
                default_value="",
                description="Name of the cached file to remove. Required for 'remove' action.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False, group_name="Default", ui_position=2
                    )
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.\n\tUsage: {}".format(DeregisterFileCommand.help_cmd))
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON blob, but got raw command line.")


class DeregisterFileCommand(CommandBase):
    cmd = "deregister_file"
    needs_admin = False
    help_cmd = "deregister_file -Action [list|remove|clear] -Name <name>"
    description = "Manage the agent's file cache. List cached files, remove a specific file, or clear the entire cache."
    version = 1
    author = "@haha150"
    argument_class = DeregisterFileArguments
    attackmapping = []
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        action = taskData.args.get_arg("action")
        name = taskData.args.get_arg("name")
        if action == "remove":
            if not name:
                raise Exception("Name is required for 'remove' action")
            response.DisplayParams = "-Action remove -Name {}".format(name)
        elif action == "clear":
            response.DisplayParams = "-Action clear"
        else:
            response.DisplayParams = "-Action list"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
