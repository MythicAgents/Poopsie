from mythic_container.MythicCommandBase import *

# Harvest port: SilentNimvest (MIT) — https://github.com/frkngksl/SilentNimvest

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
        "Dump local SAM hashes, cached domain logon credentials, and LSA secrets "
        "from the registry using the Silent Harvest technique. Returns structured JSON. "
        "Requires SeBackupPrivilege (elevated admin)."
    )
    version = 1
    author = "@m1ddl3w4r3"
    argument_class = HashdumpArguments
    attackmapping = ["T1003.002", "T1003.004", "T1003.005"]
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
