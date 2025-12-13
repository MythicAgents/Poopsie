from distutils.dir_util import copy_tree
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecuteAssemblyArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="assembly_name",
                cli_name="Assembly",
                display_name="Assembly",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="Assembly to execute (e.g., Seatbelt.exe).",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="Default", ui_position=1
                    )
                ],
            ),
            CommandParameter(
                name="assembly_file",
                display_name="New Assembly",
                type=ParameterType.File,
                description="A new assembly to execute. After uploading once, you can just supply the assembly_name parameter",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="New Assembly", ui_position=1,
                    )
                ]
            ),
            CommandParameter(
                name="assembly_arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments to pass to the assembly.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False, group_name="Default", ui_position=2
                    ),
                    ParameterGroupInfo(
                        required=False, group_name="New Assembly", ui_position=2
                    ),
                ],
            ),
            CommandParameter(
                name="patch_amsi_arg",
                cli_name="BYPASSAMSI",
                display_name="Bypass AMSI",
                type=ParameterType.Boolean,
                default_value=False,
                description="Bypass AMSI.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="Default", ui_position=3
                    ),
                    ParameterGroupInfo(
                        required=True, group_name="New Assembly", ui_position=3
                    ),
                ],
            ),
            CommandParameter(
                name="block_etw_arg",
                cli_name="BLOCKETW",
                display_name="Block ETW",
                type=ParameterType.Boolean,
                default_value=False,
                description="Block ETW.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="Default", ui_position=4
                    ),
                    ParameterGroupInfo(
                        required=True, group_name="New Assembly", ui_position=4
                    ),
                ],
            ),
        ]

    async def get_files(self, callback: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        response = PTRPCDynamicQueryFunctionMessageResponse()
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=callback.Callback,
            LimitByCallback=False,
            Filename="",
        ))
        if file_resp.Success:
            file_names = []
            for f in file_resp.Files:
                if f.Filename not in file_names and f.Filename.endswith(".exe"):
                    file_names.append(f.Filename)
            response.Success = True
            response.Choices = file_names
            return response
        else:
            await SendMythicRPCOperationEventLogCreate(MythicRPCOperationEventLogCreateMessage(
                CallbackId=callback.Callback,
                Message=f"Failed to get files: {file_resp.Error}",
                MessageLevel="warning"
            ))
            response.Error = f"Failed to get files: {file_resp.Error}"
            return response

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception(
                "Require an assembly to execute.\n\tUsage: {}".format(
                    ExecuteAssemblyCommand.help_cmd
                )
            )
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split(" ", maxsplit=1)
            self.add_arg("assembly_name", parts[0])
            self.add_arg("assembly_arguments", "")
            self.add_arg("patch_amsi_arg", parts[2])
            self.add_arg("block_etw_arg", parts[3])
            if len(parts) == 2:
                self.add_arg("assembly_arguments", parts[1])


class ExecuteAssemblyCommand(CommandBase):
    cmd = "execute_assembly"
    needs_admin = False
    help_cmd = "execute_assembly [Assembly.exe] [args]"
    description = "Executes a .NET assembly with the specified arguments. This assembly must first be known by the agent using the `register_assembly` command or by supplying an assembly with the task."
    version = 3
    author = "@djhohnstein"
    argument_class = ExecuteAssemblyArguments
    attackmapping = ["T1547"]
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
        originalGroupNameIsDefault = taskData.args.get_parameter_group_name() == "Default"
        if taskData.args.get_parameter_group_name() == "New Assembly":
            fileSearchResp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                AgentFileID=taskData.args.get_arg("assembly_file")
            ))
            if not fileSearchResp.Success:
                raise Exception(f"Failed to find uploaded file: {fileSearchResp.Error}")
            if len(fileSearchResp.Files) == 0:
                raise Exception(f"Failed to find matching file, was it deleted?")
            taskData.args.add_arg("assembly_name", fileSearchResp.Files[0].Filename)
            if fileSearchResp.Files[0].AgentFileId in taskData.Task.OriginalParams:
                response.DisplayParams = f"-Assembly {fileSearchResp.Files[0].Filename} -Arguments {taskData.args.get_arg('assembly_arguments')} -BypassAmsi {taskData.args.get_arg('patch_amsi_arg')} -BlockETW {taskData.args.get_arg('block_etw_arg')}"
            taskData.args.remove_arg("assembly_file")
            taskData.args.add_arg("uuid", fileSearchResp.Files[0].AgentFileId)
            taskData.args.add_arg("patch_amsi_arg", taskData.args.get_arg("patch_amsi_arg"))
            taskData.args.add_arg("block_etw_arg", taskData.args.get_arg("block_etw_arg"))
        else:
            fileSearchResp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=taskData.args.get_arg("assembly_name"),
                LimitByCallback=False,
            ))
            if not fileSearchResp.Success:
                raise Exception(f"Failed to find uploaded file: {fileSearchResp.Error}")
            if len(fileSearchResp.Files) == 0:
                raise Exception(f"Failed to find matching file, was it deleted?")
            taskData.args.add_arg("uuid", fileSearchResp.Files[0].AgentFileId)
            taskData.args.add_arg("assembly_name", taskData.args.get_arg("assembly_name"))
            taskData.args.add_arg("patch_amsi_arg", taskData.args.get_arg("patch_amsi_arg"))
            taskData.args.add_arg("block_etw_arg", taskData.args.get_arg("block_etw_arg"))

        taskargs = taskData.args.get_arg("assembly_arguments")
        if originalGroupNameIsDefault:
            if taskargs == "" or taskargs is None:
                response.DisplayParams = "-Assembly {}".format(
                    taskData.args.get_arg("assembly_name")
                )
            else:
                response.DisplayParams = "-Assembly {} -Arguments {}".format(
                    taskData.args.get_arg("assembly_name"), taskargs
                )
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
