from mythic_container.MythicCommandBase import *
from mythic_container.MythicGoRPC.send_mythic_rpc_callback_search import *
import json


class DisconnectArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="connection_info",
                cli_name="NewConnection",
                type=ParameterType.ConnectionInfo)
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Disconnect command requires arguments, but got empty command line.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob of arguments, but got raw command line.")
        self.load_args_from_json_string(self.command_line)

class DisconnectCommand(CommandBase):
    cmd = "disconnect"
    needs_admin = False
    help_cmd = "disconnect"
    description = "Disconnect from a TCP P2P agent."
    version = 2
    author = "@djhohnstein"
    argument_class = DisconnectArguments
    attackmapping = ["T1570", "T1572", "T1021"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        connection_info = taskData.args.get_arg("connection_info")
        if connection_info["c2_profile"]["name"] != "webshell":
            response.DisplayParams = f"{connection_info['host']} via {connection_info['c2_profile']['name']}"
            return response
        if 'callback_uuid' not in connection_info or connection_info["callback_uuid"] == "":
            response.Success = False
            response.Error = "Must select a callback to disconnect from for webshell, not a payload"
            return response
        callback_resp = await SendMythicRPCCallbackSearch(MythicRPCCallbackSearchMessage(
            AgentCallbackUUID=taskData.Callback.AgentCallbackID,
            SearchCallbackUUID=connection_info["callback_uuid"]
        ))
        if not callback_resp.Success:
            response.Success = False
            response.Error = callback_resp.Error
            return response
        if len(callback_resp.Results) == 0:
            response.Success = False
            response.Error = "Failed to find callback to disconnect from"
            return response
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
