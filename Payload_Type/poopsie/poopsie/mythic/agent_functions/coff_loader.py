from mythic_container.MythicCommandBase import *
from struct import pack, calcsize
import base64
import os
from pathlib import Path
from mythic_container.MythicRPC import *
from .utils.mythicrpc_utilities import *
from .utils.bof_utilities import upload_if_missing

class BeaconPack:
    def __init__(self):
        self.buffer : bytes = b''
        self.size   : int   = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if s is None:
            s = ''
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s)+1, s)
        self.size   += calcsize(fmt)

    def addWstr(self, s):
        if s is None:
            s = ''
        if isinstance(s, str):
            s = s.encode("utf-16_le")
        fmt = "<L{}s".format(len(s) + 2)
        self.buffer += pack(fmt, len(s)+2, s)
        self.size   += calcsize(fmt)

    def addint(self, dint):
        self.buffer += pack("<i", dint)
        self.size   += 4

    def addshort(self, n):
        self.buffer += pack("<h", n)
        self.size   += 2

    def addbytes(self, b):
        if b is None:
            b = b''
        fmt = "<L{}s".format(len(b))
        self.buffer += pack(fmt, len(b), b)
        self.size   += calcsize(fmt)

    def addbool(self, b):
        fmt = '<I'
        self.buffer += pack(fmt, 1 if b else 0)
        self.size   += 4

    def adduint32(self, n):
        fmt = '<I'
        self.buffer += pack(fmt, n)
        self.size   += 4

class CoffLoaderArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="bof_name",
                cli_name="bof",
                display_name="BOF File",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="Select an existing BOF file to execute",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
                    )
                ]
            ),
            CommandParameter(
                name="bof_file",
                display_name="New BOF",
                type=ParameterType.File,
                description="Upload a new BOF file. After uploading, you can select it from the bof_name dropdown",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="New BOF",
                        ui_position=1
                    )
                ]
            ),
            CommandParameter(
                name="args",
                cli_name="args",
                display_name="BOF Arguments",
                type=ParameterType.String,
                description="Arguments: s:str w:wstr i:123 h:42 b:true u:456 z:0xABCD (s=string, w=widestr, i=int32, h=int16, b=bool, u=uint32, z=bytes)",
                default_value="",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New BOF",
                        ui_position=2
                    )
                ]
            ),
        ]

    async def get_files(self, callback: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        from mythic_container.MythicRPC import SendMythicRPCFileSearch, MythicRPCFileSearchMessage
        response = PTRPCDynamicQueryFunctionMessageResponse()
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=callback.Callback,
            LimitByCallback=False,
            IsDownloadFromAgent=False,
            IsScreenshot=False,
            IsPayload=False,
            Filename="",
        ))
        if file_resp.Success:
            file_names = []
            for f in file_resp.Files:
                if f.Filename not in file_names and f.Filename.endswith(".o"):
                    file_names.append(f.Filename)
            response.Success = True
            response.Choices = file_names
            return response
        else:
            response.Error = f"Failed to get files: {file_resp.Error}"
            return response

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require a BOF to execute.\n\tUsage: {}".format(CoffLoaderCommand.help_cmd))
        elif self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Invalid arguments. Use JSON format.\n\tUsage: {}".format(CoffLoaderCommand.help_cmd))


class CoffLoaderCommand(CommandBase):
    cmd = "coff_loader"
    needs_admin = False
    help_cmd = "coff_loader"
    description = "Execute a Beacon Object File (BOF) using the COFFLoader DLL. Select an existing BOF or upload a new one, then specify arguments."
    version = 1
    supported_ui_features = []
    author = "@haha150"
    argument_class = CoffLoaderArguments
    attackmapping = ["T1106"]  # Native API execution
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        # Upload COFFLoader64.dll if it doesn't exist
        dll_name = "COFFLoader64.dll"
        dll_succeeded = await upload_if_missing(file_name=dll_name, taskData=taskData, upload_type="DLL")
        if not dll_succeeded:
            response.Success = False
            response.Error = f"Failed to upload or check {dll_name}"
            return response
        
        # Get the DLL UUID
        dll_search_resp = await SendMythicRPCFileSearch(
            MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=dll_name,
                LimitByCallback=False,
                MaxResults=1,
            )
        )
        
        if not dll_search_resp.Success or len(dll_search_resp.Files) == 0:
            response.Success = False
            response.Error = f"Failed to find {dll_name} after upload"
            return response
        
        dll_uuid = dll_search_resp.Files[0].AgentFileId
        
        # Handle file selection/upload
        if taskData.args.get_parameter_group_name() == "New BOF":
            # New BOF uploaded - search for it
            fileSearchResp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=taskData.args.get_arg("bof_name"),
                LimitByCallback=False,
                MaxResults=1
            ))
            if not fileSearchResp.Success:
                raise Exception(f"Failed to find uploaded file: {fileSearchResp.Error}")
            if len(fileSearchResp.Files) == 0:
                raise Exception(f"Failed to find matching file, was it deleted?")
            
            bof_name = fileSearchResp.Files[0].Filename
            file_uuid = fileSearchResp.Files[0].AgentFileId
            taskData.args.remove_arg("bof_file")
        else:
            # Existing BOF selected
            fileSearchResp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=taskData.args.get_arg("bof_name"),
                LimitByCallback=False,
                MaxResults=1
            ))
            if not fileSearchResp.Success:
                raise Exception(f"Failed to find uploaded file: {fileSearchResp.Error}")
            if len(fileSearchResp.Files) == 0:
                raise Exception(f"Failed to find matching file, was it deleted?")
            
            bof_name = fileSearchResp.Files[0].Filename
            file_uuid = fileSearchResp.Files[0].AgentFileId
        
        # Store file UUIDs - both BOF and DLL
        taskData.args.add_arg("bof_name", bof_name)
        taskData.args.add_arg("uuid", file_uuid)
        taskData.args.add_arg("dll_uuid", dll_uuid)
        
        # Pack arguments if provided
        args_spec = taskData.args.get_arg("args")
        packed_args = ""
        if args_spec and args_spec.strip():
            try:
                pack = BeaconPack()
                parts = args_spec.strip().split()
                
                for part in parts:
                    if ':' not in part:
                        raise ValueError(f"Invalid format: {part} (expected type:value)")
                    
                    arg_type, value = part.split(':', 1)
                    
                    if arg_type == 's':
                        pack.addstr(value)
                    elif arg_type == 'w':
                        pack.addWstr(value)
                    elif arg_type == 'i':
                        pack.addint(int(value))
                    elif arg_type == 'h':
                        pack.addshort(int(value))
                    elif arg_type == 'b':
                        # Boolean: accept true/false, 1/0, yes/no
                        bool_val = value.lower() in ('true', '1', 'yes', 'y')
                        pack.addbool(bool_val)
                    elif arg_type == 'u':
                        pack.adduint32(int(value))
                    elif arg_type == 'z':
                        # Raw bytes (hex string or base64)
                        if value.startswith('0x'):
                            bytes_val = bytes.fromhex(value[2:])
                        else:
                            bytes_val = base64.b64decode(value)
                        pack.addbytes(bytes_val)
                    else:
                        raise ValueError(f"Unknown type: {arg_type} (use s, w, i, h, b, u, or z)")
                
                packed_args = base64.b64encode(pack.getbuffer()).decode('utf-8')
                
            except Exception as e:
                response.Success = False
                response.Error = f"Failed to pack BOF arguments: {str(e)}"
                return response
        
        # Update the task parameters with packed args
        taskData.args.add_arg("args", packed_args)
        
        # Show display info
        if args_spec:
            response.DisplayParams = f"BOF: {bof_name}, Args: {args_spec}"
        else:
            response.DisplayParams = f"BOF: {bof_name}"
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
