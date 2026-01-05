import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import std/[json, strutils, sequtils, net, strformat, os, tables]

when defined(windows):
  import winim/lean

type
  PortScanArgs = object
    hosts: seq[string]
    ports: string
    interval: int
  
  PortScanState* = object
    allHosts: seq[string]
    allPorts: seq[int]
    interval: int
    currentHostIndex: int
    currentPortIndex: int
    openPorts: seq[tuple[host: string, port: int]]
    totalScanned: int
    output: string

var portscanActive* = false
var portscanState*: PortScanState

proc expandIpRange(ipOrCidr: string): seq[string] =
  ## Expand IP address or CIDR notation into list of IPs
  result = @[]
  
  if "/" in ipOrCidr:
    # CIDR notation - expand subnet
    let parts = ipOrCidr.split("/")
    if parts.len != 2:
      return @[ipOrCidr]  # Invalid, return as-is
    
    let baseIp = parts[0]
    let prefixLen = try: parseInt(parts[1]) except: 32
    
    # For simplicity, only support /24 and larger subnets
    if prefixLen >= 24:
      let ipParts = baseIp.split(".")
      if ipParts.len != 4:
        return @[ipOrCidr]
      
      let base = ipParts[0] & "." & ipParts[1] & "." & ipParts[2] & "."
      let hostBits = 32 - prefixLen
      let numHosts = 1 shl hostBits
      
      for i in 1..<numHosts-1:  # Skip network and broadcast
        result.add(base & $i)
    else:
      # For /16 or larger, just return the base IP to avoid huge scans
      result.add(baseIp)
  else:
    result.add(ipOrCidr)

proc expandPortRange(portStr: string): seq[int] =
  ## Expand port range string into list of ports
  ## Supports: "80", "80,443", "80-85", "80,443,1000-1005"
  result = @[]
  
  let parts = portStr.split(",")
  for part in parts:
    let trimmed = part.strip()
    if "-" in trimmed:
      let rangeParts = trimmed.split("-")
      if rangeParts.len == 2:
        let start = try: parseInt(rangeParts[0].strip()) except: 0
        let stop = try: parseInt(rangeParts[1].strip()) except: 0
        if start > 0 and stop > 0 and start <= stop:
          for p in start..stop:
            if p > 0 and p <= 65535:
              result.add(p)
    else:
      let port = try: parseInt(trimmed) except: 0
      if port > 0 and port <= 65535:
        result.add(port)

proc isPortOpen(host: string, port: int, timeout: int = 500): bool =
  ## Test if a port is open using TCP connect with short timeout
  try:
    var socket = newSocket()
    socket.connect(host, Port(port), timeout)
    socket.close()
    return true
  except:
    return false

proc portscan*(taskId: string, params: JsonNode): JsonNode =
  ## Start port scan as a background task (non-blocking)
  try:
    let args = to(params, PortScanArgs)
    
    if args.hosts.len == 0:
      return mythicError(taskId, obf("No hosts specified"))
    
    if args.ports.len == 0:
      return mythicError(taskId, obf("No ports specified"))
    
    if portscanActive:
      return mythicError(taskId, obf("A port scan is already running"))
    
    # Expand hosts (handle CIDR)
    var allHosts: seq[string] = @[]
    for hostOrCidr in args.hosts:
      allHosts.add(expandIpRange(hostOrCidr))
    
    # Expand ports (handle ranges)
    let allPorts = expandPortRange(args.ports)
    if allPorts.len == 0:
      return mythicError(taskId, obf("No valid ports specified"))
    
    debug &"[DEBUG] Port scan: {allHosts.len} hosts, {allPorts.len} ports (non-blocking)"
    debug &"[DEBUG] Interval: {args.interval}ms"
    
    # Initialize scan state
    portscanState = PortScanState(
      allHosts: allHosts,
      allPorts: allPorts,
      interval: args.interval,
      currentHostIndex: 0,
      currentPortIndex: 0,
      openPorts: @[],
      totalScanned: 0,
      output: &"\n" & obf("Scanning ") & $allHosts.len & obf(" host(s) for ") & $allPorts.len & obf(" port(s)...\n\n")
    )
    
    portscanActive = true
    
    # Return processing status - agent will poll checkPortscan
    let msg = obf("Port scan started for ") & $allHosts.len & obf(" host(s), ") & $allPorts.len & obf(" port(s) (background task)")
    return mythicProcessing(taskId, msg)
    
  except Exception as e:
    return mythicError(taskId, obf("Port scan error: ") & e.msg)

proc checkPortscan*(taskId: string): JsonNode =
  ## Check port scan progress and scan some ports (incremental scanning)
  ## This is called periodically by the agent to make progress on the scan
  if not portscanActive:
    return nil
  
  const PORTS_PER_TICK = 1  # Scan 1 port per check to avoid blocking (500ms max)
  
  try:
    var portsScanned = 0
    
    # Scan up to PORTS_PER_TICK ports
    while portsScanned < PORTS_PER_TICK and portscanActive:
      if portscanState.currentHostIndex >= portscanState.allHosts.len:
        # Scan complete
        portscanActive = false
        break
      
      let host = portscanState.allHosts[portscanState.currentHostIndex]
      let port = portscanState.allPorts[portscanState.currentPortIndex]
      
      # Scan this port with short timeout
      let isOpen = isPortOpen(host, port, 500)
      portscanState.totalScanned.inc()
      
      if isOpen:
        portscanState.openPorts.add((host: host, port: port))
        let output = &"\n" & obf("[+] ") & host & ":" & $port & obf(" OPEN\n")
        
        debug &"[DEBUG] {host}:{port} OPEN"
        
        # Return immediately with open port result (still processing)
        portscanState.currentPortIndex.inc()
        portsScanned.inc()
        
        # Move to next host if all ports scanned
        if portscanState.currentPortIndex >= portscanState.allPorts.len:
          portscanState.currentPortIndex = 0
          portscanState.currentHostIndex.inc()
        
        return mythicProcessing(taskId, output)
      
      portscanState.currentPortIndex.inc()
      portsScanned.inc()
      
      # Move to next host if all ports scanned
      if portscanState.currentPortIndex >= portscanState.allPorts.len:
        portscanState.currentPortIndex = 0
        portscanState.currentHostIndex.inc()
      
      # Sleep between scans if configured
      if portscanState.interval > 0:
        sleep(portscanState.interval)
    
    # Check if scan is complete
    if not portscanActive or portscanState.currentHostIndex >= portscanState.allHosts.len:
      portscanActive = false
      
      let finalOutput = &"\n" & obf("Port scan complete: ") & $portscanState.openPorts.len & obf(" open port(s) found out of ") & $portscanState.totalScanned & obf(" ports scanned across ") & $portscanState.allHosts.len & obf(" host(s)")
      
      debug "[DEBUG] Port scan completed"
      
      return mythicSuccess(taskId, finalOutput)
    
    return nil
    
  except Exception as e:
    portscanActive = false
    return mythicError(taskId, obf("Port scan error: ") & e.msg)
