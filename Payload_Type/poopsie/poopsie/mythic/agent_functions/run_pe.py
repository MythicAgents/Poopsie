from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class RunPeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pe_name",
                cli_name="PE",
                display_name="PE File",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="PE file to execute from existing files",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, group_name="Default", ui_position=1)
                ],
            ),
            CommandParameter(
                name="pe_file",
                display_name="New PE File",
                type=ParameterType.File,
                description="Upload a new PE file to execute",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, group_name="New PE", ui_position=1)
                ],
            ),
            CommandParameter(
                name="args",
                type=ParameterType.String,
                description="Arguments to pass to the PE (optional)",
                default_value="",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=2),
                    ParameterGroupInfo(required=False, group_name="New PE", ui_position=2)
                ],
            ),
            CommandParameter(
                name="full_tls",
                type=ParameterType.Boolean,
                description="Use full TLS patching (Windows 11+, experimental)",
                default_value=False,
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Default", ui_position=3),
                    ParameterGroupInfo(required=False, group_name="New PE", ui_position=3)
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
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
        else:
            raise ValueError("Missing arguments")


class RunPeCommand(CommandBase):
    cmd = "run_pe"
    needs_admin = False
    help_cmd = "run_pe"
    description = "Execute a PE file in memory using process hollowing (RunPE technique). Supports x86/x64 executables with full import resolution, relocations, and TLS."
    version = 1
    author = "@haha150"
    attackmapping = ["T1055"]
    argument_class = RunPeArguments
    attributes = CommandAttributes(
        suggested_command=True,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        try:
            if taskData.args.get_parameter_group_name() == "New PE":
                # Handle new PE file upload
                file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    TaskID=taskData.Task.ID,
                    AgentFileID=taskData.args.get_arg("pe_file")
                ))

                if not file_resp.Success:
                    response.Success = False
                    response.Error = f"Failed to find uploaded file: {file_resp.Error}"
                    return response

                if len(file_resp.Files) == 0:
                    response.Success = False
                    response.Error = "No file found with that ID"
                    return response

                # Build task parameters with UUID and filename
                taskData.args.add_arg("uuid", file_resp.Files[0].AgentFileId)
                taskData.args.add_arg("program_name", file_resp.Files[0].Filename)
                taskData.args.remove_arg("pe_file")
                
            else:
                # Handle existing PE file selection
                file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    TaskID=taskData.Task.ID,
                    Filename=taskData.args.get_arg("pe_name"),
                    LimitByCallback=False,
                ))

                if not file_resp.Success:
                    response.Success = False
                    response.Error = f"Failed to find file: {file_resp.Error}"
                    return response

                if len(file_resp.Files) == 0:
                    response.Success = False
                    response.Error = f"No file named '{taskData.args.get_arg('pe_name')}' found"
                    return response

                # Build task parameters with UUID and filename
                taskData.args.add_arg("uuid", file_resp.Files[0].AgentFileId)
                taskData.args.add_arg("program_name", file_resp.Files[0].Filename)

            # Build display parameters
            response.DisplayParams = f"-PE {taskData.args.get_arg('program_name')}"
            if taskData.args.get_arg("args"):
                response.DisplayParams += f" -Arguments {taskData.args.get_arg('args')}"
            if taskData.args.get_arg("full_tls"):
                response.DisplayParams += " -FullTLS True"

        except Exception as e:
            response.Success = False
            response.Error = f"Error processing arguments: {str(e)}"

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
