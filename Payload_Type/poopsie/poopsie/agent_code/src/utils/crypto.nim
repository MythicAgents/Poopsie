import std/base64
import nimcrypto/[rijndael, bcmode, sysrand, hmac, sha2]

proc generateIV*(): seq[byte] =
  ## Generate a random 16-byte IV
  result = newSeq[byte](16)
  discard randomBytes(result[0].addr, 16)

proc encryptAES256*(data: seq[byte], key: seq[byte]): seq[byte] =
  ## Encrypt data with AES-256-CBC and HMAC-SHA256
  ## Returns: IV (16 bytes) + Ciphertext + HMAC (32 bytes)
  let iv = generateIV()
  
  # Pad data to block size (16 bytes) using PKCS7
  var paddedData = data
  let padding = 16 - (data.len mod 16)
  for i in 0..<padding:
    paddedData.add(byte(padding))
  
  # Encrypt with AES-256-CBC
  var ctx: CBC[aes256]
  ctx.init(key, iv)
  
  var encrypted = newSeq[byte](paddedData.len)
  ctx.encrypt(paddedData, encrypted)
  ctx.clear()
  
  # Combine IV + Ciphertext
  let ivAndCiphertext = iv & encrypted
  
  # Calculate HMAC-SHA256 over IV + Ciphertext
  var hmacCtx: HMAC[sha256]
  hmacCtx.init(key)
  hmacCtx.update(ivAndCiphertext)
  let hmacResult = hmacCtx.finish()
  
  # Convert HMAC array to seq and append
  var hmacSeq = newSeq[byte](32)
  for i in 0..<32:
    hmacSeq[i] = hmacResult.data[i]
  
  # Final format: IV + Ciphertext + HMAC
  result = ivAndCiphertext & hmacSeq

proc decryptAES256*(data: seq[byte], key: seq[byte]): seq[byte] =
  ## Decrypt AES-256-CBC encrypted data and verify HMAC-SHA256
  ## Expects: IV (16 bytes) + Ciphertext + HMAC (32 bytes)
  if data.len < 48:  # Minimum: 16 (IV) + 0 (cipher) + 32 (HMAC)
    return @[]
  
  # Extract components
  let hmacSize = 32
  let ivAndCiphertextLen = data.len - hmacSize
  let ivAndCiphertext = data[0..<ivAndCiphertextLen]
  let receivedHmac = data[ivAndCiphertextLen..^1]
  
  # Verify HMAC-SHA256
  var hmacCtx: HMAC[sha256]
  hmacCtx.init(key)
  hmacCtx.update(ivAndCiphertext)
  let calculatedHmac = hmacCtx.finish()
  
  # Compare HMACs
  var hmacMatch = true
  for i in 0..<hmacSize:
    if receivedHmac[i] != calculatedHmac.data[i]:
      hmacMatch = false
      break
  
  if not hmacMatch:
    # HMAC verification failed
    return @[]
  
  # Extract IV and ciphertext
  let iv = ivAndCiphertext[0..<16]
  let encrypted = ivAndCiphertext[16..^1]
  
  # Decrypt
  var ctx: CBC[aes256]
  ctx.init(key, iv)
  
  var decrypted = newSeq[byte](encrypted.len)
  ctx.decrypt(encrypted, decrypted)
  ctx.clear()
  
  # Remove PKCS7 padding
  if decrypted.len > 0:
    let padding = int(decrypted[^1])
    if padding > 0 and padding <= 16:
      result = decrypted[0..<(decrypted.len - padding)]
    else:
      result = decrypted
  else:
    result = @[]

proc encryptPayload*(message: string, key: seq[byte], uuid: string): string =
  ## Encrypt a message with UUID prepended
  ## Returns: base64(UUID + encrypted_data)
  let messageBytes = cast[seq[byte]](message)
  let encrypted = encryptAES256(messageBytes, key)
  let uuidBytes = cast[seq[byte]](uuid)
  let combined = uuidBytes & encrypted
  result = encode(combined)

proc decryptPayload*(data: string, key: seq[byte], uuidLen: int = 36): string =
  ## Decrypt a base64-encoded message
  ## Expects: base64(UUID + encrypted_data)
  let decoded = decode(data)
  let decodedBytes = cast[seq[byte]](decoded)
  
  if decodedBytes.len <= uuidLen:
    return ""
  
  let encrypted = decodedBytes[uuidLen..^1]
  let decrypted = decryptAES256(encrypted, key)
  result = cast[string](decrypted)
