from mythic_container.MythicCommandBase import *
import json


class RunAsArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="credential",
                cli_name="Credential",
                display_name="Credential",
                type=ParameterType.Credential_JSON,
                limit_credentials_by_type=["plaintext"],
                parameter_group_info=[ParameterGroupInfo(
                    group_name="credential_store",
                    required=True,
                    ui_position=1
                )]
            ),
            CommandParameter(
                name="username",
                cli_name="username",
                display_name="Username",
                type=ParameterType.String,
                description="Username for authentication",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="manual",
                    required=True,
                    ui_position=1
                )]
            ),
            CommandParameter(
                name="password",
                cli_name="password",
                display_name="Password",
                type=ParameterType.String,
                description="Password for authentication",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="manual",
                    required=True,
                    ui_position=2
                )]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Domain name (use '.' for local computer)",
                default_value=".",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="credential_store",
                        ui_position=2
                    ),
                    ParameterGroupInfo(
                        group_name="manual",
                        ui_position=3
                    )
                ]
            ),
            CommandParameter(
                name="program",
                cli_name="program",
                display_name="Program",
                type=ParameterType.String,
                description="Full path to the executable to run",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="credential_store",
                        required=True,
                        ui_position=3
                    ),
                    ParameterGroupInfo(
                        group_name="manual",
                        required=True,
                        ui_position=4
                    )
                ]
            ),
            CommandParameter(
                name="args",
                cli_name="args",
                display_name="Arguments",
                type=ParameterType.String,
                description="Command-line arguments for the program",
                default_value="",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="credential_store",
                        ui_position=4
                    ),
                    ParameterGroupInfo(
                        group_name="manual",
                        ui_position=5
                    )
                ]
            ),
            CommandParameter(
                name="netonly",
                cli_name="netonly",
                display_name="Network Only Logon",
                type=ParameterType.Boolean,
                description="Use LOGON_NETCREDENTIALS_ONLY - credentials used for network access only, local identity unchanged (default: false)",
                default_value=False,
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="credential_store",
                        ui_position=5
                    ),
                    ParameterGroupInfo(
                        group_name="manual",
                        ui_position=6
                    )
                ]
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)
        # Handle credential store parameter group
        if self.get_parameter_group_name() == "credential_store":
            credential = self.get_arg("credential")
            if credential:
                try:
                    cred_data = json.loads(credential)
                    self.add_arg("username", cred_data.get("account", ""))
                    self.add_arg("password", cred_data.get("credential", ""))
                    if "realm" in cred_data and cred_data["realm"]:
                        self.add_arg("domain", cred_data["realm"])
                except Exception as e:
                    raise ValueError(f"Failed to parse credential JSON: {e}")


class RunAsCommand(CommandBase):
    cmd = "runas"
    needs_admin = False
    help_cmd = "runas"
    description = "Execute a program as another user using CreateProcessWithLogonW. Similar to Windows 'runas' command."
    version = 1
    author = "@ItsWhoAmI"
    supported_ui_features = ["runas"]
    argument_class = RunAsArguments
    attackmapping = ["T1134", "T1134.002"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=False,
        suggested_command=False
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        # Get parameters
        username = taskData.args.get_arg("username")
        password = taskData.args.get_arg("password")
        domain = taskData.args.get_arg("domain")
        program = taskData.args.get_arg("program")
        args = taskData.args.get_arg("args")
        
        # Build display output
        display_output = f"Executing as {domain}\\{username}: {program}"
        if args:
            display_output += f" {args}"
        
        response.DisplayParams = display_output
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
