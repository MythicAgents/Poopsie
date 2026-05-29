from mythic_container.MythicCommandBase import *


class HashdumpArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line.strip()) > 0:
            raise Exception("hashdump takes no command line arguments.")


class HashdumpCommand(CommandBase):
    cmd = "hashdump"
    needs_admin = True
    help_cmd = "hashdump"
    description = (
        "Dump local SAM NTLM hashes and Security hive secrets via Silent Harvest "
        "(SeBackupPrivilege, RegQueryMultipleValuesW). Returns structured JSON."
    )
    version = 1
    author = "@haha150"
    argument_class = HashdumpArguments
    supported_ui_features = []
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
