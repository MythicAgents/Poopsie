from mythic_container.MythicCommandBase import *


class ScArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["query", "start", "stop", "create", "delete"],
                default_value="query",
                description="Service control action to perform.",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=1, group_name="Default"),
                    ParameterGroupInfo(required=True, ui_position=1, group_name="Create"),
                ],
            ),
            CommandParameter(
                name="service",
                cli_name="service",
                display_name="Service Name",
                type=ParameterType.String,
                description="Name of the service.",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=2, group_name="Default"),
                    ParameterGroupInfo(required=True, ui_position=2, group_name="Create"),
                ],
            ),
            CommandParameter(
                name="computer",
                cli_name="computer",
                display_name="Remote Computer",
                type=ParameterType.String,
                default_value="",
                description="Remote computer name (leave empty for local).",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=3, group_name="Default"),
                    ParameterGroupInfo(required=False, ui_position=3, group_name="Create"),
                ],
            ),
            CommandParameter(
                name="binary_path",
                cli_name="binary_path",
                display_name="Binary Path",
                type=ParameterType.String,
                default_value="",
                description="Binary path for the service (required for create).",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=4, group_name="Create"),
                ],
            ),
            CommandParameter(
                name="display_name",
                cli_name="display_name",
                display_name="Display Name",
                type=ParameterType.String,
                default_value="",
                description="Display name for the service (defaults to service name).",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=5, group_name="Create"),
                ],
            ),
            CommandParameter(
                name="start_type",
                cli_name="start_type",
                display_name="Start Type",
                type=ParameterType.ChooseOne,
                choices=["manual", "auto", "disabled"],
                default_value="manual",
                description="Service start type.",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=6, group_name="Create"),
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split()
            if len(parts) < 2:
                raise Exception("Usage: sc <action> <service_name> [computer]")
            self.add_arg("action", parts[0])
            self.add_arg("service", parts[1])
            if len(parts) >= 3:
                self.add_arg("computer", parts[2])


class ScCommand(CommandBase):
    cmd = "sc"
    needs_admin = False
    help_cmd = "sc query <service_name> [computer]\nsc start <service_name> [computer]\nsc stop <service_name> [computer]\nsc create <service_name> -binary_path <path> [-display_name <name>] [-start_type auto|manual|disabled]\nsc delete <service_name> [computer]"
    description = "Query, start, stop, create, or delete Windows services. Supports remote targets."
    version = 1
    author = "@haha150"
    argument_class = ScArguments
    attackmapping = ["T1543.003"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        action = taskData.args.get_arg("action")
        service = taskData.args.get_arg("service")
        computer = taskData.args.get_arg("computer") or "localhost"
        
        if action == "create":
            binary_path = taskData.args.get_arg("binary_path")
            response.DisplayParams = f"{action} {service} on {computer} (binary: {binary_path})"
        else:
            response.DisplayParams = f"{action} {service} on {computer}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
