import ../config
import ../utils/mythic_responses
import std/[json, strformat, strutils]

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

proc netstat*(taskId: string, params: JsonNode): JsonNode =
  ## Get all active network connections and sockets
  let cfg = getConfig()
  
  try:
    if cfg.debug:
      echo "[DEBUG] Netstat: Getting network connections"
    
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
      # Use ss or netstat command on Linux
      try:
        let (output, exitCode) = execCmdEx("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null")
        if exitCode == 0:
          for line in output.splitLines():
            let trimmed = line.strip()
            if trimmed.len == 0 or trimmed.startsWith("Netid") or trimmed.startsWith("Proto"):
              continue
            
            let parts = trimmed.split()
            if parts.len >= 5:
              var conn = %*{
                "proto": parts[0].toUpperAscii(),
                "local_addr": "",
                "local_port": 0,
                "remote_addr": nil,
                "remote_port": nil,
                "associated_pids": newJArray(),
                "state": nil
              }
              
              # Parse local address
              if ':' in parts[3]:
                let localParts = parts[3].rsplit(':', 1)
                if localParts.len == 2:
                  conn["local_addr"] = %localParts[0]
                  try:
                    conn["local_port"] = %parseInt(localParts[1])
                  except:
                    discard
              
              # Parse remote address if available
              if parts.len > 4 and ':' in parts[4] and parts[4] != "0.0.0.0:*" and parts[4] != ":::*":
                let remoteParts = parts[4].rsplit(':', 1)
                if remoteParts.len == 2:
                  conn["remote_addr"] = %remoteParts[0]
                  try:
                    conn["remote_port"] = %parseInt(remoteParts[1])
                  except:
                    discard
              
              # Parse state for TCP
              if parts[0].toUpperAscii().startsWith("TCP") and parts.len > 1:
                conn["state"] = %parts[1]
              
              connections.add(conn)
      except:
        discard
    
    if cfg.debug:
      echo &"[DEBUG] Netstat: Found {connections.len} connections"
    
    let output = $connections
    return mythicSuccess(taskId, output)
    
  except Exception as e:
    return mythicError(taskId, &"Netstat error: {e.msg}")
