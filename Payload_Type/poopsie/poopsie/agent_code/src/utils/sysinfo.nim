import std/[os, osproc, strutils]

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

proc getSystemInfo*(): SystemInfo =
  ## Collect system information for checkin
  result = SystemInfo()
  
  # Get hostname
  try:
    when defined(windows):
      result.hostname = getEnv("COMPUTERNAME", "unknown")
    else:
      let output = execProcess("hostname")
      result.hostname = output.strip()
  except:
    result.hostname = "unknown"
  
  # Get username
  try:
    when defined(windows):
      result.user = getEnv("USERNAME", "unknown")
    else:
      result.user = getEnv("USER", "unknown")
  except:
    result.user = "unknown"
  
  # Get OS
  when defined(windows):
    result.os = "Windows"
  elif defined(macosx):
    result.os = "macOS"
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
      let output = execProcess("ipconfig")
      for line in output.splitLines():
        if "IPv4" in line:
          let parts = line.split(":")
          if parts.len > 1:
            let ip = parts[1].strip()
            if ip.len > 0:
              result.ips.add(ip)
    else:
      let output = execProcess("hostname -I")
      for ip in output.strip().split(" "):
        if ip.len > 0:
          result.ips.add(ip)
  except:
    result.ips = @["127.0.0.1"]
  
  # Get domain (Windows only for now)
  when defined(windows):
    try:
      result.domain = getEnv("USERDOMAIN", "")
    except:
      result.domain = ""
  else:
    result.domain = ""
  
  # Integrity level (simplified)
  result.integrityLevel = 2  # Medium by default
