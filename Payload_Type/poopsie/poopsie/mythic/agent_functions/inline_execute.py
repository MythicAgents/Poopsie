import binascii
from distutils.dir_util import copy_tree
import json
from struct import calcsize, pack
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

assembly_args_final = ""

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
            s = s.encode("utf-8" )
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s)+1, s)
        self.size   += calcsize(fmt)

    def addWstr(self, s):
        if s is None:
            s = ''
        s = s.encode("utf-16_le")
        fmt = "<L{}s".format(len(s) + 2)
        self.buffer += pack(fmt, len(s)+2, s)
        self.size   += calcsize(fmt)

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

    def addint(self, dint):
        self.buffer += pack("<i", dint)
        self.size   += 4

    def addshort(self, n):
        fmt = '<h'
        self.buffer += pack(fmt, n)
        self.size   += 2

class InlineExecuteArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="bof_name",
                cli_name="BOF",
                display_name="BOF",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="BOF to execute (e.g., whoami.o).",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="Default", ui_position=1
                    )
                ],
            ),
            CommandParameter(
                name="bof_file",
                display_name="New BOF",
                type=ParameterType.File,
                description="A new bof to execute. After uploading once, you can just supply the bof_name parameter",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="New BOF", ui_position=1,
                    )
                ]
            ),
            CommandParameter(
                name="bof_entrypoint",
                cli_name="Entrypoint",
                display_name="Entrypoint",
                type=ParameterType.String,
                description="Entrypoint to pass to the bof.",
                default_value="go",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="Default", ui_position=2
                    ),
                    ParameterGroupInfo(
                        required=True, group_name="New BOF", ui_position=2
                    ),
                ],
            ),
            CommandParameter(
                name="bof_arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.TypedArray,
                default_value=[],
                choices=["short", "int", "uint32", "string", "wchar", "bytes", "bool"],
                description="""Arguments to pass to the BOF via the following way:
                -s:123 or int16:123
                -i:123 or int32:123
                -z:hello or string:hello
                -Z:hello or wchar:hello
                -b:abc== or bytes:abc==""",
                typedarray_parse_function=self.get_arguments,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False, group_name="Default", ui_position=3
                    ),
                    ParameterGroupInfo(
                        required=False, group_name="New BOF", ui_position=3
                    ),
                ],
            ),
        ]

    async def get_arguments(self, arguments: PTRPCTypedArrayParseFunctionMessage) -> PTRPCTypedArrayParseFunctionMessageResponse:
        argumentSplitArray = []
        for argValue in arguments.InputArray:
            argSplitResult = argValue.split(" ")
            for spaceSplitArg in argSplitResult:
                argumentSplitArray.append(spaceSplitArg)
        bof_arguments = []
        for argument in argumentSplitArray:
            argType,value = argument.split(":",1)
            value = value.strip("\'").strip("\"")
            if argType == "":
                pass
            elif argType == "int16" or argType == "-s" or argType == "s" or argType == "short":
                bof_arguments.append(["int16", int(value)])
            elif argType == "int32" or argType == "-i" or argType == "i" or argType == "int":
                bof_arguments.append(["int32", int(value)])
            elif argType == "string" or argType == "-z" or argType == "z":
                bof_arguments.append(["string",value])
            elif argType == "wchar" or argType == "-Z" or argType == "Z" or argType == "wstr":
                bof_arguments.append(["wchar",value])
            elif argType == "bytes" or argType == "-b" or argType == "b":
                bof_arguments.append(["bytes",value])
            elif argType == "bool" or argType == "-bool" or argType == "bool":
                bof_arguments.append(["bool", value])
            elif argType == "uint32" or argType == "-I" or argType == "I":
                bof_arguments.append(["uint32", value])
            else:
                return PTRPCTypedArrayParseFunctionMessageResponse(Success=False,
                                                                   Error=f"Failed to parse argument: {argument}: Unknown value type.")

        argumentResponse = PTRPCTypedArrayParseFunctionMessageResponse(Success=True, TypedArray=bof_arguments)
        return argumentResponse

    async def get_files(self, callback: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
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
            await SendMythicRPCOperationEventLogCreate(MythicRPCOperationEventLogCreateMessage(
                CallbackId=callback.Callback,
                Message=f"Failed to get files: {file_resp.Error}",
                MessageLevel="warning"
            ))
            response.Error = f"Failed to get files: {file_resp.Error}"
            return response

    async def parse_arguments(self):
        global assembly_args_final
        if len(self.command_line) == 0:
            raise Exception(
                "Require a BOF to execute.\n\tUsage: {}".format(
                    InlineExecuteArguments.help_cmd
                )
            )
        args_bytes = ["bytes", "b"]
        args_bool = ["bool"]
        args_uinteger = ["uint32"]
        args_integer = ["int32", "i", "int"]
        args_short = ["int16", "s", "short"]
        args_string = ["string", "z", "LPCSTR", "LPSTR"]
        args_wchar = ["wchar", "Z", "LPCWSTR", "LPWSTR"]
        args_all = args_bool + args_integer + args_uinteger + args_short + args_string + args_wchar + args_bytes
        buffer = BeaconPack()

        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
            try:
                temp_dict = json.loads(self.command_line)
                assembly_args_final = ""
                bof_argumentz = temp_dict.get("bof_arguments")

                if bof_argumentz:
                    if not isinstance(bof_argumentz, list) or not all(
                        isinstance(arg, list) and len(arg) == 2 for arg in bof_argumentz
                    ):
                        raise Exception(
                            """
                            BOF arguments must be provided as a list of [type, value] pairs.\n
                            Example: [["string", "abc"], ["int32", "123"]]
                            """
                        )
                    for arg_type, arg_value in bof_argumentz:
                        try:
                            if arg_type in args_bool:
                                buffer.addbool(arg_value)
                            elif arg_type in args_integer:
                                buffer.addint(int(arg_value))
                            elif arg_type in args_uinteger:
                                buffer.adduint32(int(arg_value))
                            elif arg_type in args_short:
                                buffer.addshort(int(arg_value))
                            elif arg_type in args_string:
                                buffer.addstr(arg_value)
                            elif arg_type in args_wchar:
                                buffer.addWstr(arg_value)
                            elif arg_type in args_bytes:
                                if isinstance(arg_value, str):
                                    buffer.addbytes(bytes.fromhex(arg_value))
                                else:
                                    buffer.addbytes(arg_value)
                            else:
                                raise Exception(
                                    f"""
                                    Invalid argument type provided.\n
                                    Valid argument types (case-sensitive): {', '.join(args_all)}\n
                                    You provided {arg_type}.
                                    """
                                )
                        except ValueError:
                            raise Exception(
                                f"""
                                Invalid value provided for argument type '{arg_type}'.\n
                                Ensure the value matches the expected format for the type.
                                """
                            )
                    assembly_args_final = str(binascii.hexlify(buffer.getbuffer()), "utf-8")
                else:
                    assembly_args_final = ""

                self.add_arg("bof_file", temp_dict.get("bof_file"))
                self.add_arg("bof_entrypoint", temp_dict.get("bof_entrypoint"))
                self.add_arg("bof_arguments", temp_dict.get("bof_arguments"))
            except Exception as e:
                raise Exception(
                    "Failed to parse JSON string: {}".format(e)
                )
        else:
            raise Exception(
                "Require a JSON string to execute.\n\tUsage: {}".format(
                    InlineExecuteArguments.help_cmd
                )
            )
            

class InlineExecuteCommand(CommandBase):
    cmd = "inline_execute"
    needs_admin = False
    help_cmd = "inline_execute -BOF [bof.o] [-Arguments [optional arguments]]"
    description = "Execute a Beacon Object File in the current process thread. (e.g., inline_execute -BOF listmods.x64.o -Arguments int32:1234) \n [!!WARNING!! Incorrect argument types can crash the Agent process.]"
    version = 3
    author = "@haha150"
    argument_class = InlineExecuteArguments
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
        global assembly_args_final
        originalGroupNameIsDefault = taskData.args.get_parameter_group_name() == "Default"
        if taskData.args.get_parameter_group_name() == "New BOF":
            fileSearchResp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    TaskID=taskData.Task.ID,
                    AgentFileID=taskData.args.get_arg("bof_file")
                ))
            if not fileSearchResp.Success:
                raise Exception(f"Failed to find uploaded file: {fileSearchResp.Error}")
            if len(fileSearchResp.Files) == 0:
                raise Exception(f"Failed to find matching file, was it deleted?")
            taskData.args.add_arg("bof_name", fileSearchResp.Files[0].Filename)
            if fileSearchResp.Files[0].AgentFileId in taskData.Task.OriginalParams:
                response.DisplayParams = f"-Bof {fileSearchResp.Files[0].Filename} -Entrypoint {taskData.args.get_arg('bof_entrypoint')} -Arguments {taskData.args.get_arg('bof_arguments')}"
            taskData.args.remove_arg("bof_file")
            taskData.args.add_arg("uuid", fileSearchResp.Files[0].AgentFileId)
        else:
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
            taskData.args.add_arg("uuid", fileSearchResp.Files[0].AgentFileId)
            taskData.args.add_arg("bof_name", taskData.args.get_arg("bof_name"))
        
        taskEntrypoint = taskData.args.get_arg("bof_entrypoint")
        taskData.args.remove_arg("bof_arguments")
        taskData.args.add_arg("bof_arguments", assembly_args_final)
        taskargs = taskData.args.get_arg("bof_arguments")
        if originalGroupNameIsDefault:
            if taskargs == "" or taskargs is None:
                response.DisplayParams = "-Bof {}".format(
                    taskData.args.get_arg("bof_name")
                )
            else:
                response.DisplayParams = "-Bof {} -Entrypoint {} -Arguments {}".format(
                    taskData.args.get_arg("bof_name"),
                    taskEntrypoint,
                    taskargs,
                )
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
