import std/[os, strutils]
import strenc
import sysinfo

when defined(windows):
  when defined(evasion_dfr):
    import winim/lean except OpenProcessToken
    import winapi
  else:
    import winim/lean

when defined(linux):
  import posix

# Compile-time guardrail values from build environment
const
  guardrailHostname = static: getEnv("GUARDRAIL_HOSTNAME", "")
  guardrailDomain = static: getEnv("GUARDRAIL_DOMAIN", "")
  guardrailUsername = static: getEnv("GUARDRAIL_USERNAME", "")
  guardrailIp = static: getEnv("GUARDRAIL_IP", "")
  guardrailProcess = static: getEnv("GUARDRAIL_PROCESS", "")

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

when defined(windows):
  proc isProcessRunningApi(processName: string): bool =
    ## Check if a process is running via CreateToolhelp32Snapshot — no process spawning
    const TH32CS_SNAPPROCESS = 0x00000002'u32
    type
      PROCESSENTRY32W = object
        dwSize: DWORD
        cntUsage: DWORD
        th32ProcessID: DWORD
        th32DefaultHeapID: ULONG_PTR
        th32ModuleID: DWORD
        cntThreads: DWORD
        th32ParentProcessID: DWORD
        pcPriClassBase: LONG
        dwFlags: DWORD
        szExeFile: array[260, WCHAR]
    proc CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD): HANDLE
      {.importc: "CreateToolhelp32Snapshot", dynlib: "kernel32.dll", stdcall.}
    proc Process32FirstW(hSnapshot: HANDLE, lppe: ptr PROCESSENTRY32W): WINBOOL
      {.importc: "Process32FirstW", dynlib: "kernel32.dll", stdcall.}
    proc Process32NextW(hSnapshot: HANDLE, lppe: ptr PROCESSENTRY32W): WINBOOL
      {.importc: "Process32NextW", dynlib: "kernel32.dll", stdcall.}

    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
      return false
    defer: discard CloseHandle(snapshot)

    var entry: PROCESSENTRY32W
    entry.dwSize = DWORD(sizeof(PROCESSENTRY32W))
    let lowerName = processName.toLowerAscii()

    if Process32FirstW(snapshot, addr entry) != 0:
      while true:
        let name = $cast[WideCString](addr entry.szExeFile[0])
        if name.toLowerAscii() == lowerName:
          return true
        if Process32NextW(snapshot, addr entry) == 0:
          break
    return false

when defined(linux):
  proc isProcessRunningProc(processName: string): bool =
    ## Check if a process is running by walking /proc — no process spawning
    let lowerName = processName.toLowerAscii()
    try:
      for kind, path in walkDir(obf("/proc")):
        if kind == pcDir:
          let dirName = path.extractFilename()
          # Only look at numeric directories (PIDs)
          var isNumeric = true
          for c in dirName:
            if c < '0' or c > '9':
              isNumeric = false
              break
          if isNumeric and dirName.len > 0:
            try:
              let comm = readFile(path / obf("comm")).strip()
              if comm.toLowerAscii() == lowerName:
                return true
            except:
              discard
    except:
      discard
    return false

proc checkGuardrails*(): bool =
  ## Check all configured execution guardrails.
  ## Returns true if all guardrails pass (or are disabled).
  ## Returns false if any guardrail fails - agent should exit silently.

  # Collect system info using the same API-based approach as checkin
  when guardrailHostname.len > 0 or guardrailDomain.len > 0 or
       guardrailUsername.len > 0 or guardrailIp.len > 0:
    let info = getSystemInfo()

  # Hostname check
  when guardrailHostname.len > 0:
    if info.hostname.toLowerAscii() != guardrailHostname.toLowerAscii():
      return false

  # Domain check
  when guardrailDomain.len > 0:
    if info.domain.toLowerAscii() != guardrailDomain.toLowerAscii():
      return false

  # Username check
  when guardrailUsername.len > 0:
    if info.user.toLowerAscii() != guardrailUsername.toLowerAscii():
      return false

  # IP address check (supports exact match and CIDR)
  when guardrailIp.len > 0:
    var ipMatch = false
    if "/" in guardrailIp:
      for ip in info.ips:
        if ipInCidr(ip, guardrailIp):
          ipMatch = true
          break
    else:
      for ip in info.ips:
        if ip == guardrailIp:
          ipMatch = true
          break
    if not ipMatch:
      return false

  # Process check — use native API, no process spawning
  when guardrailProcess.len > 0:
    when defined(windows):
      if not isProcessRunningApi(guardrailProcess):
        return false
    elif defined(linux):
      if not isProcessRunningProc(guardrailProcess):
        return false

  return true
