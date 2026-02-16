from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PowershellImportArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="File",
                display_name="PowerShell Script (.ps1)",
                type=ParameterType.File,
                description="The PowerShell script to import into the agent's memory.",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require arguments.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)


class PowershellImportCommand(CommandBase):
    cmd = "powershell_import"
    needs_admin = False
    help_cmd = "powershell_import (modal popup to select .ps1 file)"
    description = (
        "Import a PowerShell script (.ps1) into the agent's memory (encrypted). "
        "Once imported, scripts can be selectively loaded using the 'scripts' "
        "parameter in powershell or powerpick commands. Use powershell_list "
        "to see all imported scripts."
    )
    version = 1
    author = "@haha150"
    argument_class = PowershellImportArguments
    attackmapping = ["T1059.001"]
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
        file_resp = await SendMythicRPCFileSearch(
            MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID, AgentFileID=taskData.args.get_arg("file")
            )
        )
        if file_resp.Success:
            original_file_name = file_resp.Files[0].Filename
        else:
            raise Exception(
                "Failed to fetch uploaded file from Mythic (ID: {})".format(
                    taskData.args.get_arg("file")
                )
            )

        taskData.args.add_arg(
            "file_name", original_file_name, type=ParameterType.String
        )

        response.DisplayParams = "-File {}".format(original_file_name)
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
