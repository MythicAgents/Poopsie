from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *

class RedirectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="port", 
                cli_name="Port",
                display_name="Port",
                type=ParameterType.Number,
                description="Port to listen for connections on the target host.",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    ui_position=1,
                )]
            ),
            CommandParameter(
                name="remote_port",
                cli_name="RemotePort",
                display_name="Remote Port",
                type=ParameterType.Number,
                description="Remote port to send redirect traffic to.",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    ui_position=2,
                )]
            ),
            CommandParameter(
                name="remote_ip",
                cli_name="RemoteIP",
                display_name="Remote IP",
                type=ParameterType.String,
                description="Remote IP to send rpfwd traffic to.",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    ui_position=3,
                )]
            ),
            CommandParameter(
                name="action",
                cli_name="Action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                default_value="start",
                description="Start or stop port redirect.",
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=4,
                    required=True
                )],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must be passed a port on the command line.")
        try:
            self.load_args_from_json_string(self.command_line)
        except:
            port = self.command_line.lower().strip()
            try:
                self.add_arg("port", int(port))
            except Exception as e:
                raise Exception("Invalid port number given: {}. Must be int.".format(port))


class RedirectCommand(CommandBase):
    cmd = "redirect"
    needs_admin = False
    help_cmd = (
        "redirect -Port 445 -RemoteIP 1.2.3.4 -RemotePort 80"
    )
    description = "Start listening on a port on the target host and forwarding traffic to the remoteIP:remotePort. Stop this with -Action stop"
    version = 1
    author = "@haha150"
    argument_class = RedirectArguments
    attackmapping = ["T1090"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        # Redirect does NOT proxy through Mythic - it's direct TCP forwarding on the agent
        # No need to register with Mythic's proxy system
        action = taskData.args.get_arg("action")
        if action == "start":
            response.DisplayParams = f"-Action start on port {taskData.args.get_arg('port')} sending to {taskData.args.get_arg('remote_ip')}:{taskData.args.get_arg('remote_port')}"
        else:
            response.DisplayParams = f"-Action stop on port {taskData.args.get_arg('port')}"
        return response


    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
