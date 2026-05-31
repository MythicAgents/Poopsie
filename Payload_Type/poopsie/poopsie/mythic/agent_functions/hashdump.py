from mythic_container.MythicCommandBase import (
    TaskArguments,
    CommandBase,
    CommandAttributes,
    SupportedOS,
    MythicTask,
    PTTaskMessageAllData,
    PTTaskProcessResponseMessageResponse,
)


class HashdumpArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class HashdumpCommand(CommandBase):
    cmd = "hashdump"
    needs_admin = True
    help_cmd = "hashdump"
    description = (
        "Dump local SAM hashes, cached domain logon credentials, and LSA secrets "
        "from the registry using the Silent Harvest technique. Uses NtOpenKeyEx with "
        "REG_OPTION_BACKUP_RESTORE and RegQueryMultipleValuesW for stealthy registry "
        "access that only requires SeBackupPrivilege (no SYSTEM needed)."
    )
    version = 1
    author = ""
    argument_class = HashdumpArguments
    attackmapping = ["T1003.002", "T1003.004", "T1003.005"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: str
    ) -> PTTaskProcessResponseMessageResponse:
        pass
