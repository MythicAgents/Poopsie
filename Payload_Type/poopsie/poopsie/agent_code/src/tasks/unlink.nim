when not defined(windows):
  {.error: "Unlink command (SMB) is only supported on Windows".}

import std/[json, strformat, tables]
import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import link

type
  HANDLE = int
  BOOL = int32

proc CloseHandle(hObject: HANDLE): BOOL {.importc, stdcall, dynlib: "kernel32".}

proc handleUnlink*(taskId: string, params: JsonNode): JsonNode =
  ## Handle unlinking from an SMB P2P agent by agent UUID
  try:
    let connInfo = params[obf("connection_info")]
    let agentUuid = connInfo[obf("agent_uuid")].getStr("")

    if agentUuid.len == 0:
      return mythicError(taskId, "No agent_uuid provided")

    # Search the table - try direct key lookup first, then iterate by stored agentUuid
    var conn: LinkConnection = nil
    var foundKey = ""

    if activeLinkConnections.hasKey(agentUuid):
      conn = activeLinkConnections[agentUuid]
      foundKey = agentUuid
    else:
      # The table may be keyed by a different UUID (staging vs callback),
      # so iterate and check the stored agentUuid field too
      for key, c in activeLinkConnections:
        if c.agentUuid == agentUuid:
          conn = c
          foundKey = key
          break

    if conn == nil:
      debug &"[DEBUG] Unlink: Looking for {agentUuid}, active connections:"
      for key, c in activeLinkConnections:
        debug &"  - key={key} agentUuid={c.agentUuid} active={c.active}"
      return mythicError(taskId, &"No active link connection for agent {agentUuid}")

    if not conn.active and conn.receivedEof:
      return mythicError(taskId, &"Connection to {agentUuid} is already closed")

    debug &"[DEBUG] Unlink: Unlinking from SMB agent {agentUuid}"

    # Signal the connection to stop
    conn.active = false
    if not conn.sharedPtr.isNil:
      conn.sharedPtr.active = false

    # Close the pipe handle to unblock the reader thread (blocking on ReadFile)
    try:
      discard CloseHandle(conn.pipeHandle)
    except:
      discard

    # Send EOF to writer thread to break it out of waiting
    conn.inChannel[].send(@[])

    # Mark as received EOF so the check loop will send edge removal
    conn.receivedEof = true

    debug &"[DEBUG] Unlink: Successfully initiated unlink from {agentUuid}"

    return mythicSuccess(taskId, &"Unlinked from SMB agent {agentUuid}")

  except Exception as e:
    debug &"[DEBUG] Unlink error: {e.msg}"
    return mythicError(taskId, &"Failed to unlink: {e.msg}")
