from mythic_container.MythicCommandBase import *
import re


class DownloadArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Path to file to download.",
                type=ParameterType.String,
                description="File to download.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
                    )
                ]),
        ]

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)
        if "host" in dictionary_arguments:
            if "full_path" in dictionary_arguments:
                self.add_arg("path", dictionary_arguments["full_path"])
            elif "path" in dictionary_arguments:
                self.add_arg("path", dictionary_arguments["path"])
            elif "file" in dictionary_arguments:
                self.add_arg("path", dictionary_arguments["file"])
            else:
                return
        else:
            if "path" not in dictionary_arguments or dictionary_arguments["path"] is None:
                self.add_arg("path", ".")

    async def parse_arguments(self):
        args = {"path": "."}
        if len(self.raw_command_line) > 0:
            args["path"] = self.raw_command_line
        self.load_args_from_dictionary(args)


class DownloadCommand(CommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "download [path/to/file]"
    description = "Download a file from the target system with chunked transfer."
    version = 1
    supported_ui_features = ["file_browser:download"]
    author = "@djhohnstein"
    argument_class = DownloadArguments
    attackmapping = ["T1020", "T1030", "T1041"]
    browser_script = BrowserScript(script_name="download", author="@djhohnstein", for_new_ui=True)
    attributes = CommandAttributes(
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        path = taskData.args.get_arg("path")
        response.DisplayParams = path

        taskData.args.add_arg("host", "")
        taskData.args.add_arg("file", path.split("/")[-1].split("\\")[-1])
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
