'''
Ref: https://github.com/MythicAgents/Athena/blob/main/Payload_Type/athena/athena/mythic/agent_functions/athena_utils/bof_utilities.py
'''
import struct
import subprocess
import os
import logging
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

from .mythicrpc_utilities import *


# This function merge the output of the subtasks and mark the parent task as completed.
async def default_coff_completion_callback(completionMsg: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    out = ""
    response = PTTaskCompletionFunctionMessageResponse(Success=True, TaskStatus="success", Completed=True)
    responses = await SendMythicRPCResponseSearch(MythicRPCResponseSearchMessage(TaskID=completionMsg.SubtaskData.Task.ID))
    for output in responses.Responses:
        out += str(output.Response)
            
    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
        TaskID=completionMsg.TaskData.Task.ID,
        Response=f"{out}"
    ))
    return response

class CoffCommandBase(CommandBase):
    completion_functions = {"coff_completion_callback": default_coff_completion_callback}

async def upload_if_missing(file_name: str, taskData, upload_type):
    """
    Upload a BOF or EXE to Mythic only if it doesn't already exist for the given task.
    """

    try:
        if upload_type == "SA":
            # Construct path dynamically, e.g. woopsie/mythic/SA/arp/arp.x64.o
            module_path = (
                Path("woopsie/mythic/SA")
                / file_name.split(".")[0]
                / file_name
            )
        elif upload_type == "BOF":
            module_path = (
                Path("woopsie/mythic/bof")
                / file_name.split(".")[0]
                / file_name
            )
        elif upload_type == "DLL":
            # For DLL files in the dll directory
            module_path = Path("woopsie/mythic/dll") / file_name
        elif upload_type == "EXE":
            module_path = Path("/exe") / file_name
        else:   
            logging.error(f"[Upload] Unknown upload type: {upload_type}")
            return False

        # Search for existing file
        search_resp = await SendMythicRPCFileSearch(
            MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=file_name,
                LimitByCallback=False,
                MaxResults=1,
            )
        )

        if not search_resp.Success:
            logging.error(f"[BOF Upload] File search failed for {file_name}: {search_resp.Error}")
            return False

        existing_names = {f.Filename for f in search_resp.Files}
        if file_name in existing_names:
            logging.info(f"[BOF Upload] {file_name} already exists in Mythic, skipping upload.")
            return True

        # Read and upload the BOF
        with open(module_path, "rb") as bof_file:
            bof_bytes = bof_file.read()

        upload_resp = await SendMythicRPCFileCreate(
            MythicRPCFileCreateMessage(
                TaskID=taskData.Task.ID,
                Filename=file_name,
                DeleteAfterFetch=False,
                FileContents=bof_bytes,
            )
        )

        if upload_resp.Success:
            logging.info(f"[BOF Upload] Successfully uploaded: {file_name}")
            return True
        else:
            logging.error(f"[BOF Upload] Failed to upload {file_name}: {upload_resp.Error}")
            return False

    except FileNotFoundError:
        logging.error(f"[BOF Upload] File not found: {module_path}")
        return False
    except Exception as e:
        logging.exception(f"[BOF Upload] Unexpected error while processing {file_name}: {str(e)}")
        return False
