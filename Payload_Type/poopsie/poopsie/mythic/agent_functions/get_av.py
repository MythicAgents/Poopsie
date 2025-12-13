from mythic_container.MythicCommandBase import *

class GetAvArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line.strip()) > 0:
            raise Exception("get_av takes no command line arguments.")
        pass


class GetAvCommand(CommandBase):
    cmd = "get_av"
    needs_admin = False
    help_cmd = "get_av"
    description = "Query installed antivirus products via WMI (Windows only)."
    version = 1
    author = "@haha150"
    argument_class = GetAvArguments
    supported_ui_features = []
    attackmapping = ["T1518.001"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
