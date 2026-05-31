from mythic_container.MythicCommandBase import *


class WebcamListArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class WebcamListCommand(CommandBase):
    cmd = "webcam_list"
    needs_admin = False
    help_cmd = "webcam_list"
    description = "List available webcam devices (USB cameras, integrated laptop cameras, etc.)."
    version = 1
    author = "@haha150"
    argument_class = WebcamListArguments
    attackmapping = ["T1125"]
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
