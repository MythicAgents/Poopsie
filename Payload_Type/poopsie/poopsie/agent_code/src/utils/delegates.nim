# https://github.com/chvancooten/NimPlant/blob/main/client/util/risky/delegates.nim

import winim/lean

type
  NtOpenProcess* = proc(
    ProcessHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    ClientId: PCLIENT_ID
  ): NTSTATUS {.stdcall.}

  NtAllocateVirtualMemory* = proc(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: PSIZE_T,
    AllocationType: ULONG,
    Protect: ULONG
  ): NTSTATUS {.stdcall.}

  NtWriteVirtualMemory* = proc(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    Buffer: PVOID,
    NumberOfBytesToWrite: SIZE_T,
    NumberOfBytesWritten: PSIZE_T
  ): NTSTATUS {.stdcall.}

  NtProtectVirtualMemory* = proc(
    ProcessHandle: HANDLE,
    BaseAddress: ptr PVOID,
    RegionSize: PSIZE_T,
    NewProtect: ULONG,
    OldProtect: PULONG
  ): NTSTATUS {.stdcall.}

  NtCreateThreadEx* = proc(
    ThreadHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    ProcessHandle: HANDLE,
    StartRoutine: PVOID,
    Argument: PVOID,
    CreateFlags: ULONG,
    ZeroBits: SIZE_T,
    StackSize: SIZE_T,
    MaximumStackSize: SIZE_T,
    AttributeList: PVOID
  ): NTSTATUS {.stdcall.}
