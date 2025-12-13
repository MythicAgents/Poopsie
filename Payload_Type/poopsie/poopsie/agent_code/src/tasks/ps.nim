import ../config
import std/[json, strformat, strutils, os]

type
  ProcessEntry = object
    process_id: uint32
    architecture: string
    name: string
    user: string
    bin_path: string
    parent_process_id: uint32
    command_line: string

when defined(windows):
  import winim
  import std/widestrs
  
  proc getProcessUser(hProcess: HANDLE): string =
    ## Get the user associated with a process
    var hToken: HANDLE = 0
    if OpenProcessToken(hProcess, TOKEN_QUERY, addr hToken) == 0:
      return ""
    
    defer: CloseHandle(hToken)
    
    # Get the size needed for token user info (TokenUser = 1)
    var dwLength: DWORD = 0
    discard GetTokenInformation(hToken, 1, nil, 0, addr dwLength)
    
    if dwLength == 0:
      return ""
    
    # Allocate buffer and get token user info
    var buffer = newSeq[byte](dwLength)
    if GetTokenInformation(hToken, 1, addr buffer[0], dwLength, addr dwLength) == 0:
      return ""
    
    # Extract SID from TOKEN_USER structure
    let pTokenUser = cast[ptr TOKEN_USER](addr buffer[0])
    let userSid = pTokenUser.User.Sid
    
    # Lookup account name from SID
    var nameSize: DWORD = 256
    var domainSize: DWORD = 256
    var nameBuffer = newSeq[char](nameSize)
    var domainBuffer = newSeq[char](domainSize)
    var sidType: SID_NAME_USE
    
    if LookupAccountSidA(nil, userSid, addr nameBuffer[0], addr nameSize, 
                         addr domainBuffer[0], addr domainSize, addr sidType) == 0:
      return ""
    
    let domain = $cast[cstring](addr domainBuffer[0])
    let name = $cast[cstring](addr nameBuffer[0])
    
    if domain.len > 0:
      result = domain & "\\" & name
    else:
      result = name
  
  proc getProcessListWindows(): seq[ProcessEntry] =
    result = @[]
    
    var pe32: PROCESSENTRY32W
    pe32.dwSize = sizeof(PROCESSENTRY32W).DWORD
    
    let hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hSnapshot == INVALID_HANDLE_VALUE:
      return
    
    if Process32FirstW(hSnapshot, addr pe32) != 0:
      while true:
        var entry: ProcessEntry
        entry.process_id = pe32.th32ProcessID.uint32
        entry.parent_process_id = pe32.th32ParentProcessID.uint32
        entry.name = $cast[WideCString](addr pe32.szExeFile[0])
        entry.architecture = hostCPU  # x86_64 or i386
        entry.user = ""
        entry.bin_path = ""
        entry.command_line = ""
        
        # Open process to query information
        let hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pe32.th32ProcessID)
        if hProcess != 0:
          # Get user
          entry.user = getProcessUser(hProcess)
          CloseHandle(hProcess)
        
        # Try to get module path
        let hModSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID)
        if hModSnapshot != INVALID_HANDLE_VALUE:
          var me32: MODULEENTRY32W
          me32.dwSize = sizeof(MODULEENTRY32W).DWORD
          if Module32FirstW(hModSnapshot, addr me32) != 0:
            entry.bin_path = $cast[WideCString](addr me32.szExePath[0])
          CloseHandle(hModSnapshot)
        
        result.add(entry)
        
        if Process32NextW(hSnapshot, addr pe32) == 0:
          break
    
    CloseHandle(hSnapshot)

when not defined(windows):
  import std/osproc
  
  proc getProcessListLinux(): seq[ProcessEntry] =
    result = @[]
    
    # Read /proc directory
    for kind, path in walkDir("/proc"):
      if kind == pcDir:
        let dirname = lastPathPart(path)
        # Check if directory name is a number (PID)
        try:
          let pid = parseInt(dirname).uint32
          
          var entry: ProcessEntry
          entry.process_id = pid
          entry.architecture = hostCPU
          
          # Read /proc/[pid]/stat
          try:
            let statContent = readFile(path / "stat")
            # Parse stat file: pid (name) state ppid ...
            let nameStart = statContent.find('(')
            let nameEnd = statContent.rfind(')')
            if nameStart > 0 and nameEnd > nameStart:
              entry.name = statContent[nameStart+1..<nameEnd]
              let afterName = statContent[nameEnd+2..^1].split(' ')
              if afterName.len > 1:
                entry.parent_process_id = parseInt(afterName[1]).uint32
          except:
            entry.name = "?"
            entry.parent_process_id = 0
          
          # Read /proc/[pid]/cmdline
          try:
            var cmdline = readFile(path / "cmdline")
            cmdline = cmdline.replace('\0', ' ').strip()
            entry.command_line = if cmdline.len > 0: cmdline else: &"[{entry.name}]"
          except:
            entry.command_line = &"[{entry.name}]"
          
          # Read /proc/[pid]/status for Uid
          try:
            let statusContent = readFile(path / "status")
            for line in statusContent.splitLines():
              if line.startsWith("Uid:"):
                let parts = line.split()
                if parts.len > 1:
                  let uid = parts[1]
                  # Try to get username from /etc/passwd
                  try:
                    let (output, _) = execCmdEx(&"getent passwd {uid}")
                    let passwdParts = output.split(':')
                    if passwdParts.len > 0:
                      entry.user = passwdParts[0]
                    else:
                      entry.user = uid
                  except:
                    entry.user = uid
                break
          except:
            entry.user = "?"
          
          # Try to get binary path
          try:
            entry.bin_path = expandSymlink(path / "exe")
          except:
            entry.bin_path = ""
          
          result.add(entry)
        except ValueError:
          continue

proc ps*(params: string): JsonNode =
  let cfg = getConfig()
  
  if cfg.debug:
    echo "[DEBUG] Getting process list"
  
  try:
    when defined(windows):
      let processes = getProcessListWindows()
      let platform = "Windows " & hostCPU
    else:
      let processes = getProcessListLinux()
      let platform = "Linux " & hostCPU
    
    # Create JSON array for processes
    var processesJson = newJArray()
    for p in processes:
      processesJson.add(%*{
        "process_id": p.process_id,
        "architecture": p.architecture,
        "name": p.name,
        "user": p.user,
        "bin_path": p.bin_path,
        "parent_process_id": p.parent_process_id,
        "command_line": p.command_line
      })
    
    # Create the full listing structure
    let listing = %*{
      "platform": platform,
      "processes": processesJson
    }
    
    if cfg.debug:
      echo &"[DEBUG] Found {processes.len} processes"
    
    return %*{
      "task_id": "",  # Will be set by agent
      "status": "success",
      "completed": true,
      "user_output": $listing,
      "processes": processesJson
    }
    
  except Exception as e:
    return %*{
      "user_output": &"Failed to get process list: {e.msg}",
      "completed": true,
      "status": "error"
    }
