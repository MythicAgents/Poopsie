from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

class PowershellListArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class PowershellListCommand(CommandBase):
    cmd = "powershell_list"
    needs_admin = False
    help_cmd = "powershell_list"
    description = (
        "List all PowerShell scripts currently imported into the agent's memory. "
        "Shows script names and sizes. Use the script names with the 'scripts' "
        "parameter in powershell or powerpick commands to selectively load them."
    )
    version = 1
    author = "@haha150"
    argument_class = PowershellListArguments
    attackmapping = []
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
