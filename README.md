<p align="center">
  <img alt="Poopsie Logo" src="agent_icons/poopsie.svg" height="25%" width="25%">
</p>

# Poopsie

Poopsie is a cross-platform C2 agent for the Mythic framework, written in Nim. It is designed to be lightweight, efficient, and feature-rich, making it suitable for red team operations across various environments.

## Features

- **Cross-platform**: Supports Windows and Linux
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
- `inline_execute` - Execute position-independent shellcode in-process
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

## Token Impersonation

Poopsie features comprehensive token impersonation support:

- **make_token**: Creates a logon session with credentials and impersonates the user at the thread level
  - Supports both network-only (`LOGON32_LOGON_NEW_CREDENTIALS`) and interactive (`LOGON32_LOGON_INTERACTIVE`) logon types
  - Automatically reports impersonation context to Mythic
  
- **steal_token**: Duplicates an impersonation token from a running process by PID
  - Uses `DuplicateTokenEx` with proper security impersonation level
  - Works with thread-level token impersonation
  
- **Thread-Level Impersonation**: All file operations automatically respect the impersonated thread token
  - Network file operations (UNC paths) use impersonated credentials
  - Process creation via `run` uses `CreateProcessAsUserW` to spawn processes as the impersonated user
  - `whoami` uses `GetUserNameExW` to correctly report the impersonated user

## UNC Path Support

Poopsie supports UNC paths for remote file operations when using impersonated credentials:

- **Commands with host parameter**: `ls`, `upload`, `rm` accept a `host` parameter that automatically builds UNC paths
- **Commands with direct UNC support**: `cat`, `download`, `cp`, `mv`, `mkdir` accept full UNC paths directly (e.g., `\\server\share\file.txt`)
- **Limitation**: `cd` cannot change to UNC paths (Windows limitation) - use `net use` to map a drive letter first

## Installation

1. Clone this repository into your Mythic server's `Mythic/InstalledServices/` directory
2. From the Mythic server, run: `sudo ./mythic-cli install folder /path/to/Poopsie/`
3. Start the Mythic server: `sudo ./mythic-cli start`

## Building

The agent is automatically built by Mythic when creating a payload. Compilation options include:

- **Output Type**: Executable (default), shellcode, or DLL
- **Debug Mode**: Enable detailed logging for troubleshooting
- **Sleep Obfuscation**: Configure sleep obfuscation technique
- **Self Delete**: Optional self-deletion after execution

## Development

Poopsie is written in Nim and uses:
- `winim/lean` for Windows API bindings
- `std/json` for Mythic protocol communication
- Cross-compilation with MinGW for Windows targets

## Credits

Poopsie is inspired by and incorporates techniques from various open-source projects in the red team community.
