# Taken from the excellent SilentNimvest project by @frkngksl (MIT)
# Source: https://github.com/frkngksl/SilentNimvest

import std/strutils
import des/des
import checksums/sha2
import nimcrypto

proc ComputeSha256*(key: seq[byte], value:seq[byte]):seq[byte] = 
  var shaBase = newSeq[byte](0)
  shaBase.add(key)
  for i in countup(0,999):
    shaBase.add(value[0..<32])
  var hasher = initSha_256()
  var charSeq = newSeq[char](shaBase.len)
  copyMem(addr charSeq[0],addr shaBase[0],shaBase.len)
  hasher.update(charSeq)
  let digest = hasher.digest()
  var returnValue = newSeq[byte](digest.len)
  copyMem(addr returnValue[0],addr digest[0],digest.len)
  return returnValue

proc RC4Encrypt*(key: seq[byte], data: seq[byte]): seq[byte] =
  var S = newSeq[int](256)
  var K = newSeq[int](256)
  var j:int = 0
  var tempVal:int = 0 
  var returnValue:seq[byte] = @[]

  # Initialize S and K arrays
  for i in 0 .. 255:
    S[i] = i
    K[i] = int(key[i mod key.len])
  # Key scheduling algorithm
  for i in 0 .. 255:
    j = (j + S[i] + K[i]) mod 256
    tempVal = S[i]
    S[i] = S[j]
    S[j] = tempVal
  # Pseudo-random generation algorithm
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
# Example usage

proc TransformKey(inputData: seq[byte]): seq[byte] =
  result.add(byte(((inputData[0] shr 1) and 0x7f) shl 1))
  result.add(byte(((inputData[0] and 0x01) shl 6 or ((inputData[1] shr 2) and 0x3f)) shl 1))
  result.add(byte(((inputData[1] and 0x03) shl 5 or ((inputData[2] shr 3) and 0x1f)) shl 1))
  result.add(byte(((inputData[2] and 0x07) shl 4 or ((inputData[3] shr 4) and 0x0f)) shl 1))
  result.add(byte(((inputData[3] and 0x0f) shl 3 or ((inputData[4] shr 5) and 0x07)) shl 1))
  result.add(byte(((inputData[4] and 0x1f) shl 2 or ((inputData[5] shr 6) and 0x03)) shl 1))
  result.add(byte(((inputData[5] and 0x3f) shl 1 or ((inputData[6] shr 7) and 0x01)) shl 1))
  result.add(byte((inputData[6] and 0x7f) shl 1))

proc RidToKey(hexRid: string): tuple[key1: seq[byte], key2: seq[byte]] =
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

  result.key1 = TransformKey(temp1)
  result.key2 = TransformKey(temp2)

proc DeObfuscateHashPart*(obfuscatedHash: seq[byte], key: seq[byte]): seq[byte] =
  var desCrypter = newDesCipher(key)
  desCrypter.setIV(@[byte 0, 0, 0, 0, 0, 0, 0, 0])
  var output = newSeq[byte](8)
  desCrypter.decrypt(obfuscatedHash, output, modeECB)
  return output




proc DecryptSingleHash*(obfuscatedHash: seq[byte], user: string): string =
  if obfuscatedHash.len < 16:
    raise newException(ValueError, "hashdump harvest failed: hash ciphertext too short")
  let (key1, key2) = RidToKey(user)

  let hashBytes1 = obfuscatedHash[0 ..< 8]
  let hashBytes2 = obfuscatedHash[8 ..< 16]

  let plain1 = DeObfuscateHashPart(hashBytes1, key1)
  let plain2 = DeObfuscateHashPart(hashBytes2, key2)

  for b in plain1: result.add(b.toHex(2))
  for b in plain2: result.add(b.toHex(2))


proc Pad*(data:int):int =
  (data + 3) and not 3

proc DecryptAES_CBC*(encryptedData:seq[byte],key:seq[byte],iv:seq[byte]):seq[byte] =
  if encryptedData.len == 0 or (encryptedData.len mod 16) != 0:
    return @[]
  var
    dctx_cbc : CBC[aes128]
    decryptedCBC = newSeq[byte](encryptedData.len)
  dctx_cbc.init(addr key[0], addr iv[0])
  dctx_cbc.decrypt(addr encryptedData[0], addr decryptedCBC[0], cast[uint](encryptedData.len))
  dctx_cbc.clear()
  return decryptedCBC


proc Md4Hash2*(input: seq[byte]): seq[byte] =
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

    doRound(f1, [0'u32, 4, 8, 12], [0'u32, 1, 2, 3],  [3'u32, 7, 11, 19], 0'u32)
    doRound(f2, [0'u32, 1, 2,  3], [0'u32, 4, 8, 12], [3'u32, 5,  9, 13], 0x5a827999'u32)
    doRound(f3, [0'u32, 2, 1,  3], [0'u32, 8, 4, 12], [3'u32, 9, 11, 15], 0x6ed9eba1'u32)

    a += aa; b += bb; c += cc; d += dd
    q += 16

  for val in [a, b, c, d]:
    result.add(byte(val and 0xff))
    result.add(byte((val shr 8) and 0xff))
    result.add(byte((val shr 16) and 0xff))
    result.add(byte((val shr 24) and 0xff))