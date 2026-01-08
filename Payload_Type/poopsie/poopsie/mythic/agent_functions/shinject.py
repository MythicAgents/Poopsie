from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ShInjectArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="PID",
                display_name="PID",
                type=ParameterType.Number,
                description="Process ID to inject into.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
                    ),
                ]),
            CommandParameter(
                name="shellcode_name",
                cli_name="shellcode_name",
                display_name="Shellcode File",
                type=ParameterType.File,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=2
                    ),
                ]),
            CommandParameter(
                name="encryption",
                cli_name="encryption",
                display_name="Encryption Method",
                type=ParameterType.ChooseOne,
                choices=["none", "xor_single", "xor_multi", "xor_counter", "xor_feedback", "xor_rolling", "rc4", "chacha20"],
                default_value="none",
                description="Shellcode encryption method",
                parameter_group_info=[ParameterGroupInfo(required=False, group_name="Default", ui_position=3)]
            ),
            CommandParameter(
                name="key",
                cli_name="key",
                display_name="Encryption Key",
                type=ParameterType.String,
                default_value="",
                description="Encryption key (hex or plain text)",
                parameter_group_info=[ParameterGroupInfo(required=False, group_name="Default", ui_position=4)]
            ),
            CommandParameter(
                name="iv",
                cli_name="iv",
                display_name="IV (xor_feedback)",
                type=ParameterType.String,
                default_value="",
                description="Initialization vector for xor_feedback",
                parameter_group_info=[ParameterGroupInfo(required=False, group_name="Default", ui_position=5)]
            ),
            CommandParameter(
                name="nonce",
                cli_name="nonce",
                display_name="Nonce (chacha20)",
                type=ParameterType.String,
                default_value="",
                description="Nonce for ChaCha20 (12 bytes)",
                parameter_group_info=[ParameterGroupInfo(required=False, group_name="Default", ui_position=6)]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.\n\tUsage: {}".format(ShInjectCommand.help_cmd))
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.\n\tUsage: {}".format(ShInjectCommand.help_cmd))
        self.load_args_from_json_string(self.command_line)
        pass


class ShInjectCommand(CommandBase):
    cmd = "shinject"
    needs_admin = False
    help_cmd = "shinject (modal popup)"
    description = "Inject shellcode into a remote process."
    version = 2
    author = "@haha150"
    argument_class = ShInjectArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "-PID {}".format(taskData.args.get_arg("pid"))
        if taskData.args.get_arg("shellcode_name") is not None:
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                AgentFileID=taskData.args.get_arg("shellcode_name"),
                TaskID=taskData.Task.ID,
            ))
            if file_resp.Success:
                original_file_name = file_resp.Files[0].Filename
            else:
                raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(taskData.args.get_arg("shellcode_name")))
            taskData.args.add_arg("uuid", file_resp.Files[0].AgentFileId)
            response.DisplayParams += " -File {}".format(original_file_name)
        else:
            raise Exception("No file provided.")
        if taskData.args.get_arg("encryption") is not None:
            response.DisplayParams += " -Encryption {}".format(taskData.args.get_arg("encryption"))
        if taskData.args.get_arg("key") is not None:
            response.DisplayParams += " -Key {}".format(taskData.args.get_arg("key"))
        if taskData.args.get_arg("iv") is not None:
            response.DisplayParams += " -IV {}".format(taskData.args.get_arg("iv"))
        if taskData.args.get_arg("nonce") is not None:
            response.DisplayParams += " -Nonce {}".format(taskData.args.get_arg("nonce"))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
