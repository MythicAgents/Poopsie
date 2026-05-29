# Ported from SilentNimvest (MIT) - https://github.com/frkngksl/SilentNimvest

import winim/lean
import std/[json, strutils]

type
  HashdumpResult* = object
    local_users*: seq[JsonNode]
    cached_logons*: seq[JsonNode]
    dpapi_machine_key*: string
    dpapi_user_key*: string
    nlkm*: string
    lsa_secrets*: seq[JsonNode]
    machine_account*: string

proc initHashdumpResult*(): HashdumpResult =
  HashdumpResult()

proc hashdumpResultToJson*(r: HashdumpResult): JsonNode =
  %*{
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
  result.UserLength      = cast[int16]([data[0], data[1]])
  result.DomainNameLength = cast[int16]([data[2], data[3]])
  result.DnsDomainLength  = cast[int16]([data[60], data[61]])
  result.Iv              = data[64 ..< 64+16]
  result.EncryptedData   = data[96 ..< 96+data.len-96]



proc NewLsaSecretBlob*(inputData: seq[byte]): LsaSecretBlob =
  let slice = inputData[0..<4]
  var index:int = 0
  result.Length = (cast[ptr uint32](addr slice[0]))[]
  result.Unk = inputData[4 ..< 16]
  result.Secret = inputData[16 ..< 16 + result.Length]
  result.SecretString = newWString(0)
  while index <  result.Secret.len:
    result.SecretString.add(cast[WCHAR](result.Secret[index]))
    index=index+2

proc SeqToUnicode*(input: seq[byte]): string =
  var index = 0
  var returnValue = newWString(0)
  while index < input.len:
    returnValue.add(cast[WCHAR](input[index]))
    index += 2
  return $returnValue

proc hexStringToByteArray*(s: string): seq[byte] =
  var i = 0
  result = newSeq[byte](0)
  while i < s.len:
    result.add(parseHexInt(s[i .. i+1]).byte)
    i += 2
  return result
