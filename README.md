<p align="center">
  <img alt="Poopsie Logo" src="agent_icons/poopsie.svg" height="25%" width="25%">
</p>

# Poopsie

Poopsie is a cross-platform C2 agent for the Mythic framework, written in Nim. It is designed to be lightweight, efficient, and feature-rich, making it suitable for red team operations across various environments.

## Features

- **Cross-platform**: Supports Windows and Linux
- **Multiple C2 Profiles**: http, httpx, websocket, dns, tcp, smb
- **Token Impersonation**: Full support for `make_token` and `steal_token` with thread-level impersonation
- **Network Operations**: UNC path support for remote file operations with impersonated credentials
- **Process Injection**: Advanced injection capabilities with `shinject` and `inline_execute`
- **SOCKS Proxy**: Built-in SOCKS5 proxy support for pivoting
- **Assembly Execution**: Load and execute .NET assemblies in-memory
- **PowerShell**: Execute PowerShell commands without `powershell.exe` via PowerPick
- **Lightweight**: Small binary size with optimized compilation flags

## Supported Commands

### File Operations
- `cat` - Read file contents (supports UNC paths)
- `cd` - Change current directory
- `cp` - Copy files (supports UNC paths)
- `download` - Download files from target (supports UNC paths, chunked)
- `ls` - List directory contents (supports UNC paths via host parameter)
- `mkdir` - Create directories (supports UNC paths)
- `mv` - Move/rename files (supports UNC paths)
- `pwd` - Print working directory
- `rm` - Remove files/directories (supports UNC paths via host parameter)
- `upload` - Upload files to target (supports UNC paths via host parameter, chunked)

### Process & Execution
- `execute_assembly` - Execute .NET assemblies in-memory
- `inline_execute` - Coff loader, execute beacon object files.
- `powerpick` - Execute PowerShell without `powershell.exe`
- `ps` - List running processes
- `pty` - Spawn an interactive pseudo-terminal
- `run` - Execute programs (respects impersonation tokens with `CreateProcessAsUserW`)
- `shinject` - Inject shellcode into remote processes
- `sleep` - Adjust callback interval and jitter

### Token & Authentication
- `make_token` - Create logon session and impersonate user (supports both `LOGON32_LOGON_NEW_CREDENTIALS` and `LOGON32_LOGON_INTERACTIVE`)
- `rev2self` - Revert to original process token
- `steal_token` - Duplicate and impersonate token from target process
- `whoami` - Display current user context (shows impersonated user when active)

### Information Gathering
- `clipboard` - Get current clipboard contents (Windows)
- `clipboard_monitor` - Monitor clipboard changes for a duration (Windows, background task)
- `get_av` - Enumerate installed antivirus products (Windows)
- `portscan` - Scan hosts for open TCP ports (background task, incremental scanning)
- `screenshot` - Capture screenshot of the desktop

### Advanced Injection
- `donut` - Execute .NET assemblies via donut-generated shellcode (Windows)
- `inject_hollow` - Inject shellcode into remote processes via process hollowing (Windows)

### Network
- `socks` - Start/stop SOCKS5 proxy for pivoting

### Miscellaneous
- `exit` - Terminate the agent

## Installation
To install Poopsie, you will need [Mythic](https://github.com/its-a-feature/Mythic) set up on a machine.

In the Mythic root directory, use `mythic-cli` to install the agent.
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/Poopsie
sudo ./mythic-cli payload start poopsie
```

or

1. Clone this repository
2. From the Mythic server, run: `sudo ./mythic-cli install folder /path/to/Poopsie/`
3. Start the Mythic server: `sudo ./mythic-cli start`

## Building

The agent is automatically built by Mythic when creating a payload. Compilation options include:

- **Output Type**: Executable (default), Shellcode, DLL, or Service
- **Architecture**: x64 or x86
- **Security Options**:
  - Message encryption (AES-256)
  - Payload compression (UPX)
  - Shellcode encryption (XOR variants, RC4, ChaCha20)
- **Evasion Options**:
  - Debug Mode - Enable detailed logging for troubleshooting
  - Sleep Obfuscation - Configure sleep obfuscation technique (Ekko for x64 Windows)
  - Self Delete - Optional self-deletion after execution (Windows & Linux)
  - Daemonize - Hide console window or run in background

## Development

Poopsie is written in Nim and uses:
- `winim/lean` for Windows API bindings
- `std/json` for Mythic protocol communication
- Cross-compilation with MinGW for Windows targets

## Credits

- Author: @haha150
- Poopsie is inspired by and incorporates techniques from various open-source projects in the red team community.
- Your friendly neighborhood LLM
