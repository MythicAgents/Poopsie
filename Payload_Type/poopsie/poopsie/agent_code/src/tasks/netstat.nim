import ../utils/mythic_responses
import ../utils/debug
import std/[json, strformat, strutils, osproc, os]

when defined(windows):
  import winim/lean
  
  const
    AF_INET = 2
    AF_INET6 = 23
    
  type
    MIB_TCP_STATE = enum
      MIB_TCP_STATE_CLOSED = 1
      MIB_TCP_STATE_LISTEN = 2
      MIB_TCP_STATE_SYN_SENT = 3
      MIB_TCP_STATE_SYN_RCVD = 4
      MIB_TCP_STATE_ESTAB = 5
      MIB_TCP_STATE_FIN_WAIT1 = 6
      MIB_TCP_STATE_FIN_WAIT2 = 7
      MIB_TCP_STATE_CLOSE_WAIT = 8
      MIB_TCP_STATE_CLOSING = 9
      MIB_TCP_STATE_LAST_ACK = 10
      MIB_TCP_STATE_TIME_WAIT = 11
      MIB_TCP_STATE_DELETE_TCB = 12
    
    MIB_TCPROW_OWNER_PID = object
      dwState: DWORD
      dwLocalAddr: DWORD
      dwLocalPort: DWORD
      dwRemoteAddr: DWORD
      dwRemotePort: DWORD
      dwOwningPid: DWORD
    
    MIB_TCPTABLE_OWNER_PID = object
      dwNumEntries: DWORD
      table: array[1, MIB_TCPROW_OWNER_PID]
    
    MIB_TCP6ROW_OWNER_PID = object
      ucLocalAddr: array[16, byte]
      dwLocalScopeId: DWORD
      dwLocalPort: DWORD
      ucRemoteAddr: array[16, byte]
      dwRemoteScopeId: DWORD
      dwRemotePort: DWORD
      dwState: DWORD
      dwOwningPid: DWORD
    
    MIB_TCP6TABLE_OWNER_PID = object
      dwNumEntries: DWORD
      table: array[1, MIB_TCP6ROW_OWNER_PID]
    
    MIB_UDPROW_OWNER_PID = object
      dwLocalAddr: DWORD
      dwLocalPort: DWORD
      dwOwningPid: DWORD
    
    MIB_UDPTABLE_OWNER_PID = object
      dwNumEntries: DWORD
      table: array[1, MIB_UDPROW_OWNER_PID]
    
    MIB_UDP6ROW_OWNER_PID = object
      ucLocalAddr: array[16, byte]
      dwLocalScopeId: DWORD
      dwLocalPort: DWORD
      dwOwningPid: DWORD
    
    MIB_UDP6TABLE_OWNER_PID = object
      dwNumEntries: DWORD
      table: array[1, MIB_UDP6ROW_OWNER_PID]
  
  proc GetExtendedTcpTable(pTcpTable: pointer, pdwSize: ptr DWORD, bOrder: WINBOOL,
                          ulAf: ULONG, TableClass: DWORD, Reserved: ULONG): DWORD
    {.importc, dynlib: "iphlpapi.dll", stdcall.}
  
  proc GetExtendedUdpTable(pUdpTable: pointer, pdwSize: ptr DWORD, bOrder: WINBOOL,
                          ulAf: ULONG, TableClass: DWORD, Reserved: ULONG): DWORD
    {.importc, dynlib: "iphlpapi.dll", stdcall.}
  
  proc ntohl(netlong: uint32): uint32 =
    ((netlong and 0xFF000000'u32) shr 24) or
    ((netlong and 0x00FF0000'u32) shr 8) or
    ((netlong and 0x0000FF00'u32) shl 8) or
    ((netlong and 0x000000FF'u32) shl 24)
  
  proc ntohs(netshort: uint16): uint16 =
    ((netshort and 0xFF00'u16) shr 8) or
    ((netshort and 0x00FF'u16) shl 8)
  
  proc stateToString(state: DWORD): string =
    case state
    of 1: "CLOSED"
    of 2: "LISTEN"
    of 3: "SYN_SENT"
    of 4: "SYN_RCVD"
    of 5: "ESTABLISHED"
    of 6: "FIN_WAIT1"
    of 7: "FIN_WAIT2"
    of 8: "CLOSE_WAIT"
    of 9: "CLOSING"
    of 10: "LAST_ACK"
    of 11: "TIME_WAIT"
    of 12: "DELETE_TCB"
    else: "UNKNOWN"
  
  proc ipv4ToString(ipAddr: DWORD): string =
    let ipVal = ntohl(ipAddr)
    let b1 = (ipVal shr 24) and 0xFF
    let b2 = (ipVal shr 16) and 0xFF
    let b3 = (ipVal shr 8) and 0xFF
    let b4 = ipVal and 0xFF
    return &"{b1}.{b2}.{b3}.{b4}"
  
  proc ipv6ToString(ipAddr: array[16, byte]): string =
    var parts: seq[string] = @[]
    for i in countup(0, 14, 2):
      let word = (ipAddr[i].uint16 shl 8) or ipAddr[i+1].uint16
      parts.add(&"{word:x}")
    return parts.join(":")

when defined(posix):
  import std/osproc

proc parseHexIP(hex: string): string =
  ## Parse hex IP address (little-endian) from /proc/net to dotted decimal
  ## Example: 0100007F -> 127.0.0.1
  if hex.len != 8:
    return "0.0.0.0"
  try:
    let a = parseHexInt(hex[6..7])
    let b = parseHexInt(hex[4..5])
    let c = parseHexInt(hex[2..3])
    let d = parseHexInt(hex[0..1])
    return &"{a}.{b}.{c}.{d}"
  except:
    return "0.0.0.0"

proc parseHexIPv6(hex: string): string =
  ## Parse hex IPv6 address from /proc/net to standard format
  ## Example: 00000000000000000000000001000000 -> ::1
  if hex.len != 32:
    return "::"
  try:
    var parts: seq[string] = @[]
    # Read in groups of 4 hex chars, but in little-endian order (reverse each group of 8)
    for i in countup(0, 28, 8):
      let group = hex[i+6..i+7] & hex[i+4..i+5] & hex[i+2..i+3] & hex[i..i+1]
      let val = parseHexInt(group)
      parts.add(&"{val:x}")
    return parts.join(":")
  except:
    return "::"

proc parseTcpState(stateHex: string): string =
  ## Parse TCP state from hex to string
  try:
    let state = parseHexInt(stateHex)
    case state
    of 0x01: return "ESTABLISHED"
    of 0x02: return "SYN_SENT"
    of 0x03: return "SYN_RECV"
    of 0x04: return "FIN_WAIT1"
    of 0x05: return "FIN_WAIT2"
    of 0x06: return "TIME_WAIT"
    of 0x07: return "CLOSE"
    of 0x08: return "CLOSE_WAIT"
    of 0x09: return "LAST_ACK"
    of 0x0A: return "LISTEN"
    of 0x0B: return "CLOSING"
    else: return "UNKNOWN"
  except:
    return "UNKNOWN"

proc netstat*(taskId: string, params: JsonNode): JsonNode =
  ## Get all active network connections and sockets
  try:
    debug "[DEBUG] Netstat: Getting network connections"
    
    var connections = newJArray()
    
    when defined(windows):
      # TCP IPv4
      var tcpTableSize: DWORD = 0
      discard GetExtendedTcpTable(nil, addr tcpTableSize, 0, AF_INET, 5, 0)  # 5 = TCP_TABLE_OWNER_PID_ALL
      
      if tcpTableSize > 0:
        var tcpBuffer = newSeq[byte](tcpTableSize)
        let tcpResult = GetExtendedTcpTable(addr tcpBuffer[0], addr tcpTableSize, 0, AF_INET, 5, 0)
        
        if tcpResult == 0:
          let tcpTable = cast[ptr MIB_TCPTABLE_OWNER_PID](addr tcpBuffer[0])
          let tcpRows = cast[ptr UncheckedArray[MIB_TCPROW_OWNER_PID]](addr tcpTable.table[0])
          
          for i in 0..<tcpTable.dwNumEntries:
            let row = tcpRows[i]
            var conn = %*{
              "proto": "TCP",
              "local_addr": ipv4ToString(row.dwLocalAddr),
              "local_port": ntohs(uint16(row.dwLocalPort)),
              "remote_addr": ipv4ToString(row.dwRemoteAddr),
              "remote_port": ntohs(uint16(row.dwRemotePort)),
              "associated_pids": [row.dwOwningPid],
              "state": stateToString(row.dwState)
            }
            connections.add(conn)
      
      # TCP IPv6
      var tcp6TableSize: DWORD = 0
      discard GetExtendedTcpTable(nil, addr tcp6TableSize, 0, AF_INET6, 5, 0)
      
      if tcp6TableSize > 0:
        var tcp6Buffer = newSeq[byte](tcp6TableSize)
        let tcp6Result = GetExtendedTcpTable(addr tcp6Buffer[0], addr tcp6TableSize, 0, AF_INET6, 5, 0)
        
        if tcp6Result == 0:
          let tcp6Table = cast[ptr MIB_TCP6TABLE_OWNER_PID](addr tcp6Buffer[0])
          let tcp6Rows = cast[ptr UncheckedArray[MIB_TCP6ROW_OWNER_PID]](addr tcp6Table.table[0])
          
          for i in 0..<tcp6Table.dwNumEntries:
            let row = tcp6Rows[i]
            var conn = %*{
              "proto": "TCP6",
              "local_addr": ipv6ToString(row.ucLocalAddr),
              "local_port": ntohs(uint16(row.dwLocalPort)),
              "remote_addr": ipv6ToString(row.ucRemoteAddr),
              "remote_port": ntohs(uint16(row.dwRemotePort)),
              "associated_pids": [row.dwOwningPid],
              "state": stateToString(row.dwState)
            }
            connections.add(conn)
      
      # UDP IPv4
      var udpTableSize: DWORD = 0
      discard GetExtendedUdpTable(nil, addr udpTableSize, 0, AF_INET, 1, 0)  # 1 = UDP_TABLE_OWNER_PID
      
      if udpTableSize > 0:
        var udpBuffer = newSeq[byte](udpTableSize)
        let udpResult = GetExtendedUdpTable(addr udpBuffer[0], addr udpTableSize, 0, AF_INET, 1, 0)
        
        if udpResult == 0:
          let udpTable = cast[ptr MIB_UDPTABLE_OWNER_PID](addr udpBuffer[0])
          let udpRows = cast[ptr UncheckedArray[MIB_UDPROW_OWNER_PID]](addr udpTable.table[0])
          
          for i in 0..<udpTable.dwNumEntries:
            let row = udpRows[i]
            var conn = %*{
              "proto": "UDP",
              "local_addr": ipv4ToString(row.dwLocalAddr),
              "local_port": ntohs(uint16(row.dwLocalPort)),
              "remote_addr": nil,
              "remote_port": nil,
              "associated_pids": [row.dwOwningPid],
              "state": nil
            }
            connections.add(conn)
      
      # UDP IPv6
      var udp6TableSize: DWORD = 0
      discard GetExtendedUdpTable(nil, addr udp6TableSize, 0, AF_INET6, 1, 0)
      
      if udp6TableSize > 0:
        var udp6Buffer = newSeq[byte](udp6TableSize)
        let udp6Result = GetExtendedUdpTable(addr udp6Buffer[0], addr udp6TableSize, 0, AF_INET6, 1, 0)
        
        if udp6Result == 0:
          let udp6Table = cast[ptr MIB_UDP6TABLE_OWNER_PID](addr udp6Buffer[0])
          let udp6Rows = cast[ptr UncheckedArray[MIB_UDP6ROW_OWNER_PID]](addr udp6Table.table[0])
          
          for i in 0..<udp6Table.dwNumEntries:
            let row = udp6Rows[i]
            var conn = %*{
              "proto": "UDP6",
              "local_addr": ipv6ToString(row.ucLocalAddr),
              "local_port": ntohs(uint16(row.dwLocalPort)),
              "remote_addr": nil,
              "remote_port": nil,
              "associated_pids": [row.dwOwningPid],
              "state": nil
            }
            connections.add(conn)
    
    when defined(posix):
      # Read directly from /proc/net/tcp and /proc/net/udp like oopsie does
      try:
        # Parse /proc/net/tcp
        if fileExists("/proc/net/tcp"):
          let tcpData = readFile("/proc/net/tcp")
          for line in tcpData.splitLines()[1..^1]:  # Skip header
            let parts = line.strip().split()
            if parts.len >= 10:
              # Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
              # Example: 0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 28629
              
              # Parse local address (hex IP:hex port)
              if ':' in parts[1]:
                let localParts = parts[1].split(':')
                if localParts.len == 2:
                  try:
                    let localIp = parseHexIP(localParts[0])
                    let localPort = parseHexInt(localParts[1])
                    
                    var conn = %*{
                      "proto": "TCP",
                      "local_addr": localIp,
                      "local_port": localPort,
                      "remote_addr": nil,
                      "remote_port": nil,
                      "associated_pids": newJArray(),
                      "state": parseTcpState(parts[3])
                    }
                    
                    # Parse remote address
                    if ':' in parts[2]:
                      let remoteParts = parts[2].split(':')
                      if remoteParts.len == 2 and remoteParts[0] != "00000000":
                        try:
                          conn["remote_addr"] = %parseHexIP(remoteParts[0])
                          conn["remote_port"] = %parseHexInt(remoteParts[1])
                        except:
                          discard
                    
                    connections.add(conn)
                  except:
                    discard
        
        # Parse /proc/net/tcp6
        if fileExists("/proc/net/tcp6"):
          let tcp6Data = readFile("/proc/net/tcp6")
          for line in tcp6Data.splitLines()[1..^1]:  # Skip header
            let parts = line.strip().split()
            if parts.len >= 10:
              if ':' in parts[1]:
                let localParts = parts[1].split(':')
                if localParts.len == 2:
                  try:
                    let localIp = parseHexIPv6(localParts[0])
                    let localPort = parseHexInt(localParts[1])
                    
                    var conn = %*{
                      "proto": "TCP",
                      "local_addr": localIp,
                      "local_port": localPort,
                      "remote_addr": nil,
                      "remote_port": nil,
                      "associated_pids": newJArray(),
                      "state": parseTcpState(parts[3])
                    }
                    
                    if ':' in parts[2]:
                      let remoteParts = parts[2].split(':')
                      if remoteParts.len == 2 and remoteParts[0] != "00000000000000000000000000000000":
                        try:
                          conn["remote_addr"] = %parseHexIPv6(remoteParts[0])
                          conn["remote_port"] = %parseHexInt(remoteParts[1])
                        except:
                          discard
                    
                    connections.add(conn)
                  except:
                    discard
        
        # Parse /proc/net/udp
        if fileExists("/proc/net/udp"):
          let udpData = readFile("/proc/net/udp")
          for line in udpData.splitLines()[1..^1]:  # Skip header
            let parts = line.strip().split()
            if parts.len >= 10:
              if ':' in parts[1]:
                let localParts = parts[1].split(':')
                if localParts.len == 2:
                  try:
                    let localIp = parseHexIP(localParts[0])
                    let localPort = parseHexInt(localParts[1])
                    
                    var conn = %*{
                      "proto": "UDP",
                      "local_addr": localIp,
                      "local_port": localPort,
                      "remote_addr": nil,
                      "remote_port": nil,
                      "associated_pids": newJArray(),
                      "state": nil
                    }
                    
                    connections.add(conn)
                  except:
                    discard
        
        # Parse /proc/net/udp6
        if fileExists("/proc/net/udp6"):
          let udp6Data = readFile("/proc/net/udp6")
          for line in udp6Data.splitLines()[1..^1]:  # Skip header
            let parts = line.strip().split()
            if parts.len >= 10:
              if ':' in parts[1]:
                let localParts = parts[1].split(':')
                if localParts.len == 2:
                  try:
                    let localIp = parseHexIPv6(localParts[0])
                    let localPort = parseHexInt(localParts[1])
                    
                    var conn = %*{
                      "proto": "UDP",
                      "local_addr": localIp,
                      "local_port": localPort,
                      "remote_addr": nil,
                      "remote_port": nil,
                      "associated_pids": newJArray(),
                      "state": nil
                    }
                    
                    connections.add(conn)
                  except:
                    discard
      except:
        discard
    
    debug &"[DEBUG] Netstat: Found {connections.len} connections"
    
    let output = $connections
    return mythicSuccess(taskId, output)
    
  except Exception as e:
    return mythicError(taskId, &"Netstat error: {e.msg}")
