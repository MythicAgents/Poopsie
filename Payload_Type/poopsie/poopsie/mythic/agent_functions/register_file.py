from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RegisterFileArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="File",
                display_name="File",
                type=ParameterType.File,
                description="File to cache in agent memory.",
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
                description="Name to store the file under in the cache. This name is used to reference the file later.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="Default", ui_position=2
                    )
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.\n\tUsage: {}".format(RegisterFileCommand.help_cmd))
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON blob, but got raw command line.")


class RegisterFileCommand(CommandBase):
    cmd = "register_file"
    needs_admin = False
    help_cmd = "register_file -File <file> -Name <name>"
    description = "Download a file from Mythic and cache it in agent memory. Cached files can be used by execute_assembly, inline_execute, shinject, inject_hollow, donut, and run_pe to avoid re-downloading the same file on each execution."
    version = 1
    author = "@haha150"
    argument_class = RegisterFileArguments
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
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            AgentFileID=taskData.args.get_arg("file"),
            TaskID=taskData.Task.ID,
        ))
        if not file_resp.Success:
            raise Exception("Failed to fetch uploaded file from Mythic: {}".format(file_resp.Error))
        if len(file_resp.Files) == 0:
            raise Exception("No file found")

        original_file_name = file_resp.Files[0].Filename
        cache_name = taskData.args.get_arg("name")

        taskData.args.add_arg("uuid", file_resp.Files[0].AgentFileId)
        taskData.args.remove_arg("file")

        response.DisplayParams = "-File {} -Name {}".format(original_file_name, cache_name)
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
