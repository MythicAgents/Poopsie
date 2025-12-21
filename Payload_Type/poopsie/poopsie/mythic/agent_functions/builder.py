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

sys.path.append(str(pathlib.Path(".") / "poopsie" / "agent_code"))
from ShellcodeRDI import ConvertToShellcode, HashFunctionName


class Poopsie(PayloadType):
    name = "poopsie"
    file_extension = "exe"
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
    
    shellcode_format_options = ["Binary", "Base64", "C", "CSharp", "Hex", "Ruby", "Python"]
    shellcode_bypass_options = ["None", "Abort on fail", "Continue on fail"]
    
    build_parameters = [
        BuildParameter(
            name="output_type",
            parameter_type=BuildParameterType.ChooseOne,
            description="Output format for the payload",
            choices=["Executable", "DLL", "Service", "Shellcode"],
            default_value="Executable",
            required=True,
        ),
        BuildParameter(
            name="service_name",
            parameter_type=BuildParameterType.String,
            description="Windows service name",
            default_value="PoopsieService",
            required=False,
            group_name="Service Options",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.NotEQ, value="Service")
            ],
            supported_os=["Windows"]
        ),
        BuildParameter(
            name="tool",
            parameter_type=BuildParameterType.ChooseOne,
            description="Shellcode generation tool",
            default_value="sRDI",
            choices=["sRDI", "donut"],
            required=False,
            group_name="Shellcode Options",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.NotEQ, value="Shellcode")
            ],
            supported_os=["Windows"]
        ),
        BuildParameter(
            name="shellcode_format",
            parameter_type=BuildParameterType.ChooseOne,
            choices=shellcode_format_options,
            default_value="Binary",
            description="Donut shellcode format options. Only used if shellcode tool is donut.",
            required=False,
            group_name="Shellcode Options",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.NotEQ, value="Shellcode"),
                HideCondition(name="tool", operand=HideConditionOperand.NotEQ, value="donut")
            ],
            supported_os=["Windows"]
        ),
        BuildParameter(
            name="shellcode_bypass",
            parameter_type=BuildParameterType.ChooseOne,
            choices=shellcode_bypass_options,
            default_value="None",
            description="Donut shellcode AMSI/WLDP/ETW Bypass options. Only used if shellcode tool is donut.",
            required=False,
            group_name="Shellcode Options",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.NotEQ, value="Shellcode"),
                HideCondition(name="tool", operand=HideConditionOperand.NotEQ, value="donut")
            ],
            supported_os=["Windows"]
        ),
        BuildParameter(
            name="sRDI_flags",
            parameter_type=BuildParameterType.ChooseOne,
            description="sRDI flags (0x1 = Clear the PE header on load, 0x4 = Randomize import dependency load order, 0x8 = Pass shellcode base address to exported function)",
            default_value="0",
            choices=["0", "0x1", "0x4", "0x8"],
            required=False,
            group_name="Shellcode Options",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.NotEQ, value="Shellcode"),
                HideCondition(name="tool", operand=HideConditionOperand.NotEQ, value="sRDI")
            ],
            supported_os=["Windows"]
        ),
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
            group_name="Sleep Obfuscation Options",
            hide_conditions=[
                HideCondition(name="architecture", operand=HideConditionOperand.NotEQ, value="x64")
            ],
            required=True,
        ),
        BuildParameter(
            name="self_delete",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Enable self-deletion of the agent on exit (Windows only)",
            required=False,
            supported_os=["Windows"],
        ),
        BuildParameter(
            name="adjust_filename",
            parameter_type=BuildParameterType.Boolean,
            description="Automatically adjust payload extension based on selected choices.",
            default_value=True,
            required=False,
        ),
    ]
    
    c2_profiles = ["http", "websocket", "httpx"]

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
        BuildStep(step_name="Compiling", step_description="Building payload with Nim"),
        BuildStep(step_name="Shellcode", step_description="Converting to Shellcode"),
        BuildStep(step_name="Finalizing", step_description="Packaging final payload"),
    ]
    
    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Error)
        try:
            selected_os = self.selected_os
            
            resp.build_message += f"Building Nim payload for {selected_os}...\n"

            output_type = self.get_parameter("output_type")
            
            if selected_os == "Linux" and output_type in ["Service", "Shellcode"]:
                resp.build_message += f"Linux builds do not support output type: {output_type}\n"
                resp.status = BuildStatus.Error
                return resp
            
            if selected_os == "Windows":
                if output_type == "DLL":
                    self.file_extension = "dll"
                elif output_type == "Shellcode":
                    self.file_extension = "bin"
                else:
                    self.file_extension = "exe"
            else:
                if output_type == "DLL":
                    self.file_extension = "so"
                else:
                    self.file_extension = "bin"

            c2 = self.c2info[0]
            profile = c2.get_c2profile()["name"]

            c2_params = c2.get_parameters_dict()
            c2_params["UUID"] = self.uuid
            c2_params["profile"] = profile
            
            if profile.lower() == "websocket":
                tasking_type = c2_params.get("tasking_type", "").lower()
                if tasking_type == "push":
                    resp.build_message += "Error: WebSocket profile only supports 'Poll' tasking mode. 'Push' mode is not implemented.\n"
                    resp.build_message += "Please select 'Poll' as the tasking type in the WebSocket C2 profile configuration.\n"
                    resp.status = BuildStatus.Error
                    return resp

            c2_params["output_type"] = self.get_parameter("output_type")
            c2_params["debug"] = str(self.get_parameter("debug"))
            
            architecture = self.get_parameter("architecture")
            sleep_obfuscation = self.get_parameter("sleep_obfuscation")
            if architecture == "x86" and sleep_obfuscation == "ekko":
                c2_params["sleep_obfuscation"] = "none"
            else:
                c2_params["sleep_obfuscation"] = sleep_obfuscation
            
            c2_params["self_delete"] = str(self.get_parameter("self_delete"))
            
            if output_type == "Service":
                service_name = self.get_parameter("service_name")
                if not service_name:
                    service_name = "PoopsieService"
                c2_params["SERVICE_NAME"] = service_name

            build_env = {}
            for key, val in c2_params.items():
                if isinstance(val, str):
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
                    build_env[key.upper()] = val.strip()
                elif isinstance(val, (int, bool)):
                    build_env[key.upper()] = str(val)
                elif isinstance(val, dict):
                    build_env[key.upper()] = json.dumps(val)
                elif isinstance(val, list):
                    build_env[key.upper()] = json.dumps(val)
                else:
                    build_env[key.upper()] = str(val)

            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Configuration",
                StepStdout="Successfully prepared build configuration",
                StepSuccess=True
            ))

            resp.build_message += "\nBuild Configuration:\n"
            for key, value in build_env.items():
                display_value = value
                resp.build_message += f"  {key}: {display_value}\n"
            resp.build_message += "\n"

            output_type = self.get_parameter("output_type")
            resp.build_message += f"Compiling Nim agent ({output_type}) for {selected_os}...\n"
            build_result = await self.run_nim_build(selected_os, output_type, build_env)
            
            if "messages" in build_result:
                for msg in build_result["messages"]:
                    resp.build_message += msg + "\n"
            
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

            if output_type == "Shellcode" and selected_os == "Windows":
                resp.build_message += "Converting to shellcode...\n"
                
                dll_build_result = await self.run_nim_build(selected_os, "DLL", build_env)
                if not dll_build_result["success"]:
                    resp.build_message += f"\nDLL build for shellcode failed: {dll_build_result['error']}\n"
                    resp.status = BuildStatus.Error
                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Shellcode",
                        StepStdout=f"Failed to build DLL for shellcode conversion",
                        StepSuccess=False
                    ))
                    return resp
                
                dll_path = dll_build_result["path"]
                
                tool = self.get_parameter("tool")
                if tool == "sRDI":
                    with open(dll_path, "rb") as f:
                        dll_bytes = f.read()
                    flags = int(self.get_parameter("sRDI_flags"), 16) if self.get_parameter("sRDI_flags") else 0
                    shellcode = ConvertToShellcode(dll_bytes, HashFunctionName("entrypoint"), flags=flags)
                    output_path = self.agent_code_path / "src" / "poopsie.bin"
                    with open(output_path, "wb") as f:
                        f.write(shellcode)
                    resp.build_message += f"Successfully converted to shellcode using sRDI (flags={hex(flags)})\n"
                else:
                    output_path = self.agent_code_path / "src" / "poopsie.bin"
                    shellcode_format = self.shellcode_format_options.index(self.get_parameter('shellcode_format')) + 1
                    shellcode_bypass = self.shellcode_bypass_options.index(self.get_parameter('shellcode_bypass')) + 1
                    
                    command = f"/donut -x3 -k2 -m entrypoint -o {output_path} -i {dll_path} -f{shellcode_format} -b{shellcode_bypass}"
                    
                    proc = await asyncio.create_subprocess_shell(
                        command,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await proc.communicate()
                    
                    if proc.returncode != 0:
                        resp.build_message += f"Donut shellcode generation failed\nSTDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}\n"
                        resp.status = BuildStatus.Error
                        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Shellcode",
                            StepStdout=f"Donut failed: {stderr.decode()}",
                            StepSuccess=False
                        ))
                        return resp
                    resp.build_message += f"Successfully converted to shellcode using donut\n"
                
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Shellcode",
                    StepStdout="Successfully converted to shellcode",
                    StepSuccess=True
                ))

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
            resp.build_message += f"\nSuccessfully built Nim payload for {selected_os}\n"

            if self.get_parameter("adjust_filename"):
                resp.updated_filename = self.adjust_file_name(self.filename, selected_os)

        except Exception as e:
            resp.build_message = f"Error building payload: {str(e)}\n{traceback.format_exc()}"
            resp.status = BuildStatus.Error

        return resp

    async def run_nim_build(self, selected_os: str, output_type: str, build_env: dict) -> dict:
        """Compile Nim agent with environment variables"""
        try:
            build_messages = []
            
            env = os.environ.copy()
            env.update(build_env)
            
            architecture = self.get_parameter("architecture")
            nim_cpu = "amd64" if architecture == "x64" else "i386"
            
            encrypted_exchange = build_env.get("ENCRYPTED_EXCHANGE_CHECK", "").strip().upper()
            callback_host = build_env.get("CALLBACK_HOST", "").lower()
            profile = build_env.get("PROFILE", "").lower()
            
            needs_openssl_for_exchange = encrypted_exchange in ["T", "TRUE"]
            
            if selected_os == "Windows":
                needs_openssl_for_transport = False
            else:
                needs_openssl_for_transport = (
                    callback_host.startswith("https://") or 
                    callback_host.startswith("wss://") or
                    (profile == "websocket" and callback_host.startswith("wss://"))
                )
            
            use_openssl = needs_openssl_for_exchange or needs_openssl_for_transport
            
            nim_args = [
                "-d:release",
                "--opt:size",
                "--mm:orc",
                "--panics:on",
                "--passC:-flto",
                "--passL:-flto",
                "--passL:-s",
                "--d:strip",
                "--d:useMalloc",
                "--parallelBuild:0",
                "--threads:on",
            ]
            
            if use_openssl:
                if selected_os == "Windows":
                    if architecture == "x64":
                        openssl_path = "/opt/openssl-mingw64-static"
                        openssl_lib = f"{openssl_path}/lib64"
                    else:
                        openssl_path = "/opt/openssl-mingw32-static"
                        openssl_lib = f"{openssl_path}/lib"
                    
                    nim_args.extend([
                        "-d:staticOpenSSL",
                        f"--passC:-I{openssl_path}/include",
                        "--dynlibOverride:ssl",
                        "--dynlibOverride:crypto",
                        f"--passL:{openssl_lib}/libssl.a",
                        f"--passL:{openssl_lib}/libcrypto.a",
                        "--passL:-lws2_32",
                        "--passL:-lcrypt32",
                        "--passL:-lbcrypt",
                        "--passL:-ladvapi32",
                    ])
                    
                    build_messages.append(f"Static OpenSSL 3.5.4 enabled ({architecture}, RSA key exchange, no DLL dependencies)")
                elif selected_os == "Linux":
                    nim_args.extend([
                        "-d:ssl",
                    ])
                    if needs_openssl_for_exchange and needs_openssl_for_transport:
                        build_messages.append("Dynamic OpenSSL enabled (HTTPS/WSS transport + RSA key exchange)")
                    elif needs_openssl_for_exchange:
                        build_messages.append("Dynamic OpenSSL enabled (RSA key exchange, requires libssl.so on target)")
                    else:
                        build_messages.append("Dynamic OpenSSL enabled (HTTPS/WSS transport)")
                    build_messages.append("  Note: Target system must have OpenSSL 1.1+ or 3.x installed")
            else:
                if selected_os == "Windows":
                    build_messages.append("AESPSK mode (no RSA)")
                else:
                    build_messages.append("AESPSK mode (no RSA, standard httpclient)")
            
            if selected_os == "Windows":
                if callback_host.startswith("https://") or callback_host.startswith("wss://"):
                    build_messages.append("Custom WinHTTP client (native Windows API for HTTPS/WSS transport, no DLLs)")
            
            if output_type == "DLL":
                nim_args.extend([
                    "--app:lib",
                    "--nomain",
                    "-d:dll",
                ])
            elif output_type == "Service":
                nim_args.extend([
                    "-d:service",
                ])
            if selected_os == "Windows":
                if architecture == "x64":
                    nim_args.extend([
                        "--os:windows",
                        "--cpu:amd64",
                        "--cc:gcc",
                        "--gcc.exe:x86_64-w64-mingw32-gcc",
                        "--gcc.linkerexe:x86_64-w64-mingw32-gcc",
                        "--passL:-static"
                    ])
                else:
                    nim_args.extend([
                        "--os:windows",
                        "--cpu:i386",
                        "--cc:gcc",
                        "--gcc.exe:i686-w64-mingw32-gcc",
                        "--gcc.linkerexe:i686-w64-mingw32-gcc",
                        "--passL:-static"
                    ])
                if output_type == "DLL":
                    output_name = "poopsie.dll"
                else:
                    output_name = "poopsie.exe"
            elif selected_os == "Linux":
                nim_args.extend(["--os:linux", f"--cpu:{nim_cpu}"])
                output_name = "libpoopsie.so" if output_type == "DLL" else "poopsie"
            else:
                output_name = "libpoopsie.so" if output_type == "DLL" else "poopsie"
            
            cmd_args = ["nim", "c"] + nim_args + ["src/poopsie.nim"]
            
            if os.path.exists("/usr/lib/ccache"):
                env["PATH"] = f"/usr/lib/ccache:{env.get('PATH', '')}"
            
            env_parts = []
            for k, v in build_env.items():
                escaped_value = str(v).replace("'", "'\\''")
                env_parts.append(f"{k}='{escaped_value}'")
            env_str = ' '.join(env_parts)
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
                    "command": command,
                    "messages": build_messages
                }
            
            output_path = self.agent_code_path / "src" / output_name
            if not output_path.exists():
                return {
                    "success": False,
                    "error": f"Compiled binary not found at {output_path}",
                    "command": command,
                    "messages": build_messages
                }
            
            return {
                "success": True,
                "path": output_path,
                "command": command,
                "messages": build_messages
            }
            
        except asyncio.TimeoutError:
            return {"success": False, "error": "Build timeout (exceeded 5 minutes)", "command": command}
        except Exception as e:
            return {"success": False, "error": str(e), "command": "nimble c -y -d:release --opt:size src/poopsie.nim"}
    
    def adjust_file_name(self, filename, selected_os):
        """Adjust filename based on OS and output type"""
        filename_pieces = filename.split(".")
        original_filename = ".".join(filename_pieces[:-1])
        output_type = self.get_parameter("output_type")
        architecture = self.get_parameter("architecture")
        
        arch_suffix = f"_{architecture}"
        if not original_filename.endswith(arch_suffix):
            original_filename += arch_suffix
        
        if selected_os == "Windows":
            if output_type == "DLL":
                return original_filename + ".dll"
            elif output_type == "Shellcode":
                return original_filename + ".bin"
            else:
                return original_filename + ".exe"
        else:
            if output_type == "DLL":
                return original_filename + ".so"
            else:
                return original_filename + ".bin"


