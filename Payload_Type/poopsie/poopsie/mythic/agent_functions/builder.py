import asyncio
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from mythic_container.PayloadBuilder import *
from mythic_container.MythicRPC import *


class Poopsie(PayloadType):
    name = "poopsie"
    file_extension = "bin"
    author = "@haha150"
    supported_os = [
        SupportedOS.Windows,
        SupportedOS.Linux,
    ]
    mythic_encrypts = True
    wrapper = False
    wrapped_payloads = []
    note = "Poopsie is a cross-platform C2 agent written in Nim."
    supports_dynamic_loading = False
    supports_multiple_c2_instances_in_build = False
    supports_multiple_c2_in_build = False
    
    build_parameters = [
        BuildParameter(
            name="architecture",
            parameter_type=BuildParameterType.ChooseOne,
            description="Target architecture for the payload",
            choices=["x64", "x86"],
            default_value="x64",
            required=True,
        ),
        BuildParameter(
            name="debug",
            parameter_type=BuildParameterType.Boolean,
            description="Enable debug logging (logs all HTTP requests/responses and operations)",
            default_value=False,
            required=False,
        ),
        BuildParameter(
            name="sleep_obfuscation",
            parameter_type=BuildParameterType.ChooseOne,
            description="Sleep obfuscation technique (Windows x64 only)",
            default_value="none",
            choices=["none", "ekko"],
            required=True,
        ),
        BuildParameter(
            name="self_delete",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Enable self-deletion of the agent on exit (Windows only)",
            required=False,
        ),
        BuildParameter(
            name="adjust_filename",
            parameter_type=BuildParameterType.Boolean,
            description="Automatically adjust payload extension based on selected choices.",
            default_value=True,
            required=False,
        ),
    ]
    
    c2_profiles = ["http"]

    c2_parameter_deviations = {
        "http": {
            "get_uri": C2ParameterDeviation(supported=False),
            "query_path_name": C2ParameterDeviation(supported=False),
        }
    }

    agent_path = pathlib.Path(".") / "poopsie" / "mythic"
    agent_code_path = pathlib.Path(".") / "poopsie" / "agent_code"
    agent_icon_path = agent_path / "agent_icon" / "poopsie.svg"

    build_steps = [
        BuildStep(step_name="Configuration", step_description="Preparing build configuration"),
        BuildStep(step_name="Compiling", step_description="Building payload with Maven"),
        BuildStep(step_name="Finalizing", step_description="Packaging final payload"),
    ]
    
    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Error)
        try:
            # Get build parameters
            selected_os = self.selected_os  # Get selected OS from Mythic
            
            resp.build_message += f"Building Nim payload for {selected_os}...\n"

            # Set file extension based on OS
            if selected_os == "Windows":
                self.file_extension = "exe"
            else:
                self.file_extension = "bin"

            # Prepare environment variables for build (like oopsie does)
            c2 = self.c2info[0]
            profile = c2.get_c2profile()["name"]

            # Get all C2 parameters and add UUID like oopsie does
            c2_params = c2.get_parameters_dict()
            c2_params["UUID"] = self.uuid
            c2_params["profile"] = profile

            # Add build parameters
            c2_params["debug"] = str(self.get_parameter("debug"))
            c2_params["sleep_obfuscation"] = self.get_parameter("sleep_obfuscation")
            c2_params["self_delete"] = str(self.get_parameter("self_delete"))

            # Build environment from c2_params - convert all to env format
            build_env = {}
            for key, val in c2_params.items():
                if isinstance(val, str):
                    # Handle raw_c2_config specially - fetch file content like oopsie
                    if key == "raw_c2_config":
                        response = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(val))
                        if response.Success:
                            val = response.Content.decode('utf-8')
                            try:
                                config = json.loads(val)
                            except json.JSONDecodeError:
                                resp.build_message = f"Failed to parse raw_c2_config JSON: {val}"
                                resp.status = BuildStatus.Error
                                return resp
                            val = json.dumps(config)
                        else:
                            resp.build_message = "Failed to get raw C2 config file"
                            resp.status = BuildStatus.Error
                            return resp
                    # Sanitize all string values (strip whitespace)
                    build_env[key.upper()] = val.strip()
                elif isinstance(val, (int, bool)):
                    build_env[key.upper()] = str(val)
                elif isinstance(val, dict):
                    # Store all dicts as JSON (headers, raw_c2_config, etc.)
                    # Java will parse the headers JSON and extract all headers including User-Agent
                    build_env[key.upper()] = json.dumps(val)
                elif isinstance(val, list):
                    # Handle lists (like callback_domains for httpx)
                    build_env[key.upper()] = json.dumps(val)
                else:
                    build_env[key.upper()] = str(val)

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Configuration",
                StepStdout="Successfully prepared build configuration",
                StepSuccess=True
            ))

            # Add build environment to message for visibility
            resp.build_message += "\nBuild Configuration:\n"
            for key, value in build_env.items():
                # Mask UUID for security
                display_value = value
                resp.build_message += f"  {key}: {display_value}\n"
            resp.build_message += "\n"

            # Build Nim agent
            resp.build_message += f"Compiling Nim agent for {selected_os}...\n"
            build_result = await self.run_nim_build(selected_os, build_env)
            
            if not build_result["success"]:
                resp.build_message += f"\nNim build failed: {build_result['error']}\n"
                resp.status = BuildStatus.Error
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling",
                    StepStdout=f"Build failed: {build_result['error']}",
                    StepSuccess=False
                ))
                return resp
            
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Compiling",
                StepStdout=f"Successfully compiled Nim agent for {selected_os}",
                StepSuccess=True
            ))
            resp.build_message += f"Build command: {build_result['command']}\n"
            output_path = build_result["path"]

            # Read the final payload
            resp.build_message += "Reading final payload...\n"
            with open(output_path, "rb") as f:
                resp.payload = f.read()

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Finalizing",
                StepStdout=f"Successfully packaged Nim payload",
                StepSuccess=True
            ))

            resp.status = BuildStatus.Success
            resp.build_message += f"\n✓ Successfully built Nim payload for {selected_os}\n"

            # Adjust filename based on OS
            if self.get_parameter("adjust_filename"):
                resp.updated_filename = self.adjust_file_name(self.filename, selected_os)

        except Exception as e:
            resp.build_message = f"Error building payload: {str(e)}\n{traceback.format_exc()}"
            resp.status = BuildStatus.Error

        return resp

    async def run_nim_build(self, selected_os: str, build_env: dict) -> dict:
        """Compile Nim agent with environment variables"""
        try:
            # Set up environment
            env = os.environ.copy()
            env.update(build_env)
            
            # Get architecture selection
            architecture = self.get_parameter("architecture")
            nim_cpu = "amd64" if architecture == "x64" else "i386"
            
            # Determine target OS for cross-compilation
            nim_args = [
                "-d:release",
                "--opt:size",
                "--mm:orc",                    # Use ORC memory management (default in Nim 2.0+)
                "--panics:on",                 # Use panics instead of exceptions (smaller binary)
                "--passC:-flto",               # Link-time optimization (smaller binary)
                "--passL:-flto",               # Link-time optimization
                "--passL:-s",                  # Strip symbols (smaller binary)
                "--d:strip",                   # Strip debug info
                "--d:useMalloc",               # Use system malloc (smaller)
                "--parallelBuild:0",           # Auto-detect CPU cores for faster compilation
            ]
            if selected_os == "Windows":
                # Cross-compile for Windows using MinGW
                if architecture == "x64":
                    nim_args.extend([
                        "--os:windows",
                        "--cpu:amd64",
                        "--cc:gcc",
                        "--gcc.exe:x86_64-w64-mingw32-gcc",
                        "--gcc.linkerexe:x86_64-w64-mingw32-gcc"
                    ])
                else:  # x86
                    nim_args.extend([
                        "--os:windows",
                        "--cpu:i386",
                        "--cc:gcc",
                        "--gcc.exe:i686-w64-mingw32-gcc",
                        "--gcc.linkerexe:i686-w64-mingw32-gcc"
                    ])
                output_name = "poopsie.exe"
            elif selected_os == "Linux":
                nim_args.extend(["--os:linux", f"--cpu:{nim_cpu}"])
                output_name = "poopsie"
            elif selected_os == "MacOS":
                # Can't cross-compile to macOS, build for Linux instead
                nim_args.extend(["--os:linux", f"--cpu:{nim_cpu}"])
                output_name = "poopsie"
            else:
                output_name = "poopsie"
            
            # Build command: nim c directly (faster than nimble for rebuilds)
            # Note: Dependencies should already be installed via nimble install in Dockerfile
            cmd_args = ["nim", "c"] + nim_args + ["src/poopsie.nim"]
            
            # Enable ccache for faster recompilation (if available)
            if os.path.exists("/usr/lib/ccache"):
                env["PATH"] = f"/usr/lib/ccache:{env.get('PATH', '')}"
            
            # Build the command string for display
            env_str = ' '.join(f'{k}="{v}"' for k, v in build_env.items())
            command = f'{env_str} {" ".join(cmd_args)}'
            
            process = await asyncio.create_subprocess_exec(
                *cmd_args,
                cwd=str(self.agent_code_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            
            if process.returncode != 0:
                stdout_text = stdout.decode() if stdout else ""
                stderr_text = stderr.decode() if stderr else ""
                return {
                    "success": False,
                    "error": f"Nim compilation failed with code {process.returncode}\n\nSTDOUT:\n{stdout_text}\n\nSTDERR:\n{stderr_text}",
                    "command": command
                }
            
            # Check if output file exists (compiled binary is in src/ directory)
            output_path = self.agent_code_path / "src" / output_name
            if not output_path.exists():
                return {
                    "success": False,
                    "error": f"Compiled binary not found at {output_path}",
                    "command": command
                }
            
            return {
                "success": True,
                "path": output_path,
                "command": command
            }
            
        except asyncio.TimeoutError:
            return {"success": False, "error": "Build timeout (exceeded 5 minutes)", "command": command}
        except Exception as e:
            return {"success": False, "error": str(e), "command": "nimble c -y -d:release --opt:size src/poopsie.nim"}
    
    def adjust_file_name(self, filename, selected_os):
        """Adjust filename based on OS"""
        filename_pieces = filename.split(".")
        original_filename = ".".join(filename_pieces[:-1])
        
        if selected_os == "Windows":
            return original_filename + ".exe"
        else:
            return original_filename + ".bin"


