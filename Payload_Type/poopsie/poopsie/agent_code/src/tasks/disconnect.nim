import std/[json, strformat, tables, net]
import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import connect

proc handleDisconnect*(taskId: string, params: JsonNode): JsonNode =
  ## Handle disconnecting from a TCP P2P agent by agent UUID
  try:
    let connInfo = params[obf("connection_info")]
    let agentUuid = connInfo[obf("agent_uuid")].getStr("")

    if agentUuid.len == 0:
      return mythicError(taskId, "No agent_uuid provided")

    # Search the table - try direct key lookup first, then iterate by stored agentUuid
    var conn: ConnectConnection = nil
    var foundKey = ""

    if activeConnectConnections.hasKey(agentUuid):
      conn = activeConnectConnections[agentUuid]
      foundKey = agentUuid
    else:
      # The table may be keyed by a different UUID (staging vs callback),
      # so iterate and check the stored agentUuid field too
      for key, c in activeConnectConnections:
        if c.agentUuid == agentUuid:
          conn = c
          foundKey = key
          break

    if conn == nil:
      # Debug: log what's in the table
      debug &"[DEBUG] Disconnect: Looking for {agentUuid}, active connections:"
      for key, c in activeConnectConnections:
        debug &"  - key={key} agentUuid={c.agentUuid} active={c.active}"
      return mythicError(taskId, &"No active connect connection for agent {agentUuid}")

    if not conn.active and conn.receivedEof:
      return mythicError(taskId, &"Connection to {agentUuid} is already closed")

    debug &"[DEBUG] Disconnect: Disconnecting from TCP agent {agentUuid}"

    # Signal the connection to stop
    conn.active = false
    if not conn.sharedPtr.isNil:
      conn.sharedPtr.active = false

    # Close the socket to unblock the reader thread (blocking on recv)
    try:
      conn.socket.close()
    except:
      discard

    # Send EOF to writer thread to break it out of waiting
    conn.inChannel[].send(@[])

    # Mark as received EOF so the check loop will send edge removal
    conn.receivedEof = true

    debug &"[DEBUG] Disconnect: Successfully initiated disconnect from {agentUuid}"

    return mythicSuccess(taskId, &"Disconnected from TCP agent {agentUuid}")

  except Exception as e:
    debug &"[DEBUG] Disconnect error: {e.msg}"
    return mythicError(taskId, &"Failed to disconnect: {e.msg}")
