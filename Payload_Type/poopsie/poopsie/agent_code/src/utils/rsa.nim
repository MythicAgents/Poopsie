## RSA utilities for key exchange with Mythic C2
##
## Windows: BCrypt API (native, no DLL dependencies, works with Donut shellcode)
## Linux: Dynamic linking to system OpenSSL (requires libssl.so)

import std/[base64, strutils]

when defined(staticOpenSSL):
  # Windows BCrypt/CNG API
  type
    BCRYPT_ALG_HANDLE = pointer
    BCRYPT_KEY_HANDLE = pointer
    NTSTATUS = int32
    ULONG = uint32
    PUCHAR = ptr UncheckedArray[byte]

  type
    BCRYPT_OAEP_PADDING_INFO = object
      pszAlgId: WideCString
      pbLabel: pointer
      cbLabel: ULONG
    
  const
    STATUS_SUCCESS = 0
    BCRYPT_RSA_ALGORITHM = "RSA"
    BCRYPT_RSAFULLPRIVATE_BLOB = "RSAFULLPRIVATEBLOB"
    BCRYPT_RSAPUBLIC_BLOB = "RSAPUBLICBLOB"
    BCRYPT_PAD_OAEP = 0x00000004'u32
    
  # BCrypt API declarations
  proc BCryptOpenAlgorithmProvider(
    phAlgorithm: ptr BCRYPT_ALG_HANDLE,
    pszAlgId: WideCString,
    pszImplementation: WideCString,
    dwFlags: ULONG
  ): NTSTATUS {.stdcall, dynlib: "bcrypt.dll", importc.}
  
  proc BCryptCloseAlgorithmProvider(
    hAlgorithm: BCRYPT_ALG_HANDLE,
    dwFlags: ULONG
  ): NTSTATUS {.stdcall, dynlib: "bcrypt.dll", importc.}
  
  proc BCryptGenerateKeyPair(
    hAlgorithm: BCRYPT_ALG_HANDLE,
    phKey: ptr BCRYPT_KEY_HANDLE,
    dwLength: ULONG,
    dwFlags: ULONG
  ): NTSTATUS {.stdcall, dynlib: "bcrypt.dll", importc.}
  
  proc BCryptFinalizeKeyPair(
    hKey: BCRYPT_KEY_HANDLE,
    dwFlags: ULONG
  ): NTSTATUS {.stdcall, dynlib: "bcrypt.dll", importc.}
  
  proc BCryptDestroyKey(
    hKey: BCRYPT_KEY_HANDLE
  ): NTSTATUS {.stdcall, dynlib: "bcrypt.dll", importc.}
  
  proc BCryptExportKey(
    hKey: BCRYPT_KEY_HANDLE,
    hExportKey: BCRYPT_KEY_HANDLE,
    pszBlobType: WideCString,
    pbOutput: PUCHAR,
    cbOutput: ULONG,
    pcbResult: ptr ULONG,
    dwFlags: ULONG
  ): NTSTATUS {.stdcall, dynlib: "bcrypt.dll", importc.}
  
  proc BCryptDecrypt(
    hKey: BCRYPT_KEY_HANDLE,
    pbInput: PUCHAR,
    cbInput: ULONG,
    pPaddingInfo: pointer,
    pbIV: PUCHAR,
    cbIV: ULONG,
    pbOutput: PUCHAR,
    cbOutput: ULONG,
    pcbResult: ptr ULONG,
    dwFlags: ULONG
  ): NTSTATUS {.stdcall, dynlib: "bcrypt.dll", importc.}

  proc bcryptBlobToPem(publicKeyBlob: seq[byte]): string =
    ## Convert BCrypt RSA public key blob to PEM format (PKCS#1)
    
    if publicKeyBlob.len < 24:
      return ""

    proc simpleReverse(s: var seq[byte]) =
      let n = s.len
      for i in 0..<(n div 2):
        swap(s[i], s[n - 1 - i])
  
    # Parse BCrypt header (little-endian)
    let cbPublicExp = cast[ptr uint32](unsafeAddr publicKeyBlob[8])[]
    let cbModulus = cast[ptr uint32](unsafeAddr publicKeyBlob[12])[]
    
    if publicKeyBlob.len < 24 + cbPublicExp.int + cbModulus.int:
      return ""
    
    # Extract components
    var exponent = newSeq[byte](cbPublicExp)
    var modulus = newSeq[byte](cbModulus)

    for i in 0..<cbPublicExp.int:
      exponent[i] = publicKeyBlob[24 + i]

    for i in 0..<cbModulus.int:
      modulus[i] = publicKeyBlob[24 + cbPublicExp.int + i]

    # BCrypt might already be in big-endian for the modulus?
    # Only reverse exponent
    simpleReverse(exponent)
    
    # Build ASN.1 DER structure
    proc encodeInteger(data: seq[byte]): seq[byte] =
      var d = data
      
      # Remove leading zeros but keep at least one byte
      while d.len > 1 and d[0] == 0:
        d.delete(0)
      
      # Add leading zero if high bit is set
      if d.len > 0 and (d[0] and 0x80) != 0:
        d.insert(0, 0)
      
      result.add(0x02'u8)  # INTEGER tag
      
      let contentLen = d.len
      if contentLen < 128:
        result.add(contentLen.uint8)
      elif contentLen < 256:
        result.add(0x81'u8)
        result.add(contentLen.uint8)
      elif contentLen < 65536:
        result.add(0x82'u8)
        result.add((contentLen shr 8).uint8)
        result.add((contentLen and 0xFF).uint8)
      else:
        result.add(0x83'u8)
        result.add((contentLen shr 16).uint8)
        result.add((contentLen shr 8).uint8)
        result.add((contentLen and 0xFF).uint8)
      
      result.add(d)
    
    var modulusInt = encodeInteger(modulus)
    var exponentInt = encodeInteger(exponent)
    
    # Build SEQUENCE
    var derSeq: seq[byte] = @[]
    derSeq.add(0x30'u8)
    
    let seqContentLen = modulusInt.len + exponentInt.len
    
    if seqContentLen < 128:
      derSeq.add(seqContentLen.uint8)
    elif seqContentLen < 256:
      derSeq.add(0x81'u8)
      derSeq.add(seqContentLen.uint8)
    elif seqContentLen < 65536:
      derSeq.add(0x82'u8)
      derSeq.add((seqContentLen shr 8).uint8)
      derSeq.add((seqContentLen and 0xFF).uint8)
    else:
      derSeq.add(0x83'u8)
      derSeq.add((seqContentLen shr 16).uint8)
      derSeq.add((seqContentLen shr 8).uint8)
      derSeq.add((seqContentLen and 0xFF).uint8)
    
    derSeq.add(modulusInt)
    derSeq.add(exponentInt)
    
    # Convert to PEM
    let b64 = encode(derSeq)
    var pem = "-----BEGIN RSA PUBLIC KEY-----\n"
    
    var pos = 0
    while pos < b64.len:
      let lineLen = min(64, b64.len - pos)
      pem.add(b64[pos..<pos+lineLen])
      pem.add("\n")
      pos += lineLen
    
    pem.add("-----END RSA PUBLIC KEY-----\n")
    return pem

  type
    RsaKeyPair* = object
      hAlgorithm: BCRYPT_ALG_HANDLE
      hKey: BCRYPT_KEY_HANDLE
      publicKeyPem*: string
      available*: bool

  proc isRsaAvailable*(): bool =
    result = true  # BCrypt always available on Windows

  proc generateRsaKeyPair*(bits: int = 4096): RsaKeyPair =
    result.available = false
    result.publicKeyPem = ""
    
    var hAlg: BCRYPT_ALG_HANDLE
    
    # Open RSA algorithm provider
    if BCryptOpenAlgorithmProvider(addr hAlg, newWideCString(BCRYPT_RSA_ALGORITHM), nil, 0) != STATUS_SUCCESS:
      return
    
    var hKey: BCRYPT_KEY_HANDLE
    
    # Generate RSA key pair
    if BCryptGenerateKeyPair(hAlg, addr hKey, bits.ULONG, 0) != STATUS_SUCCESS:
      discard BCryptCloseAlgorithmProvider(hAlg, 0)
      return
    
    # Finalize the key (THIS creates the actual key pair with private key)
    if BCryptFinalizeKeyPair(hKey, 0) != STATUS_SUCCESS:
      discard BCryptDestroyKey(hKey)
      discard BCryptCloseAlgorithmProvider(hAlg, 0)
      return
    
    # Export public key for PEM
    var publicKeySize: ULONG = 0
    if BCryptExportKey(hKey, nil, newWideCString(BCRYPT_RSAPUBLIC_BLOB), nil, 0, addr publicKeySize, 0) != STATUS_SUCCESS:
      discard BCryptDestroyKey(hKey)
      discard BCryptCloseAlgorithmProvider(hAlg, 0)
      return
    
    var publicKeyBlob = newSeq[byte](publicKeySize)
    if BCryptExportKey(hKey, nil, newWideCString(BCRYPT_RSAPUBLIC_BLOB), 
                       cast[PUCHAR](addr publicKeyBlob[0]), publicKeySize, addr publicKeySize, 0) != STATUS_SUCCESS:
      discard BCryptDestroyKey(hKey)
      discard BCryptCloseAlgorithmProvider(hAlg, 0)
      return
    
    # Convert BCrypt blob to PEM format
    result.publicKeyPem = bcryptBlobToPem(publicKeyBlob)
    if result.publicKeyPem.len == 0:
      discard BCryptDestroyKey(hKey)
      discard BCryptCloseAlgorithmProvider(hAlg, 0)
      return
    
    # Store the key handle (contains both public and private key)
    result.hAlgorithm = hAlg
    result.hKey = hKey  # This handle has the private key for decryption
    result.available = true

  proc rsaPrivateDecrypt*(keyPair: RsaKeyPair, encryptedData: seq[byte]): seq[byte] =
    if not keyPair.available or encryptedData.len == 0:
      return @[]
    
    # OAEP padding info (SHA1 for compatibility with Mythic)
    var paddingInfo = BCRYPT_OAEP_PADDING_INFO(
      pszAlgId: newWideCString("SHA1"),
      pbLabel: nil,
      cbLabel: 0
    )
    
    var outputSize: ULONG = 0
    
    # Get required buffer size
    let status1 = BCryptDecrypt(
      keyPair.hKey,
      cast[PUCHAR](unsafeAddr encryptedData[0]),
      encryptedData.len.ULONG,
      addr paddingInfo,  # Pass padding info
      nil, 0,
      nil, 0,
      addr outputSize,
      BCRYPT_PAD_OAEP
    )
    
    if status1 != STATUS_SUCCESS:
      return @[]
    
    result = newSeq[byte](outputSize)

    var actualSize: ULONG = outputSize
    
    let status2 = BCryptDecrypt(
      keyPair.hKey,
      cast[PUCHAR](unsafeAddr encryptedData[0]),
      encryptedData.len.ULONG,
      cast[pointer](addr paddingInfo),
      nil,
      0,
      cast[PUCHAR](if result.len > 0: addr result[0] else: nil),
      result.len.ULONG,  # Use actual buffer length
      addr actualSize,   # Use separate variable
      BCRYPT_PAD_OAEP
    )
    
    if status2 == STATUS_SUCCESS:
      result.setLen(actualSize)
    else:
      result = @[]

  proc freeRsaKeyPair*(keyPair: var RsaKeyPair) =
    if keyPair.available:
      if not keyPair.hKey.isNil:
        discard BCryptDestroyKey(keyPair.hKey)
        keyPair.hKey = nil
      if not keyPair.hAlgorithm.isNil:
        discard BCryptCloseAlgorithmProvider(keyPair.hAlgorithm, 0)
        keyPair.hAlgorithm = nil
      keyPair.available = false

elif defined(ssl):
  # Linux: Dynamic linking to system OpenSSL (libssl.so)
  import openssl
  
  # Type aliases for compatibility
  type
    BIGNUM = SslPtr
    RSA = SslPtr
    BIO = SslPtr
    BIO_METHOD = SslPtr
    EVP_PKEY = SslPtr
    EVP_PKEY_CTX = SslPtr
  
  const
    RSA_F4 = 65537'u64
    RSA_PKCS1_OAEP_PADDING = 4
    BIO_NOCLOSE = 0
    EVP_PKEY_RSA = 6
  
  # OpenSSL functions for dynamic linking
  proc BN_new(): ptr BIGNUM {.cdecl, dynlib: DLLSSLName, importc.}
  proc BN_free(a: ptr BIGNUM) {.cdecl, dynlib: DLLSSLName, importc.}
  proc BN_set_word(a: ptr BIGNUM, w: culong): cint {.cdecl, dynlib: DLLSSLName, importc.}
  
  proc EVP_PKEY_new(): ptr EVP_PKEY {.cdecl, dynlib: DLLSSLName, importc.}
  proc EVP_PKEY_free(pkey: ptr EVP_PKEY) {.cdecl, dynlib: DLLSSLName, importc.}
  proc EVP_PKEY_CTX_new_id(id: cint, e: pointer): ptr EVP_PKEY_CTX {.cdecl, dynlib: DLLSSLName, importc.}
  proc EVP_PKEY_CTX_free(ctx: ptr EVP_PKEY_CTX) {.cdecl, dynlib: DLLSSLName, importc.}
  proc EVP_PKEY_keygen_init(ctx: ptr EVP_PKEY_CTX): cint {.cdecl, dynlib: DLLSSLName, importc.}
  proc EVP_PKEY_CTX_set_rsa_keygen_bits(ctx: ptr EVP_PKEY_CTX, mbits: cint): cint {.cdecl, dynlib: DLLSSLName, importc.}
  proc EVP_PKEY_keygen(ctx: ptr EVP_PKEY_CTX, ppkey: ptr ptr EVP_PKEY): cint {.cdecl, dynlib: DLLSSLName, importc.}
  proc EVP_PKEY_get1_RSA(pkey: ptr EVP_PKEY): ptr RSA {.cdecl, dynlib: DLLSSLName, importc.}
  
  proc RSA_free(r: ptr RSA) {.cdecl, dynlib: DLLSSLName, importc.}
  proc RSA_size(rsa: ptr RSA): cint {.cdecl, dynlib: DLLSSLName, importc.}
  proc RSA_private_decrypt(flen: cint, `from`: ptr byte, to: ptr byte,
                          rsa: ptr RSA, padding: cint): cint {.cdecl, dynlib: DLLSSLName, importc.}
  
  proc BIO_new(typ: ptr BIO_METHOD): ptr BIO {.cdecl, dynlib: DLLUtilName, importc.}
  proc BIO_free(a: ptr BIO): cint {.cdecl, dynlib: DLLUtilName, importc.}
  proc BIO_s_mem(): ptr BIO_METHOD {.cdecl, dynlib: DLLUtilName, importc.}
  proc BIO_ctrl(bp: ptr BIO, cmd: cint, larg: clong, parg: pointer): clong {.cdecl, dynlib: DLLUtilName, importc.}
  proc BIO_read(b: ptr BIO, data: pointer, dlen: cint): cint {.cdecl, dynlib: DLLUtilName, importc.}
  proc PEM_write_bio_RSAPublicKey(bp: ptr BIO, x: ptr RSA): cint {.cdecl, dynlib: DLLSSLName, importc.}
  
  template BIO_get_mem_data(b: ptr BIO, pp: untyped): clong =
    BIO_ctrl(b, 3, 0, pp)

  type
    RsaKeyPair* = object
      pkey: ptr EVP_PKEY
      rsa: ptr RSA
      publicKeyPem*: string
      available*: bool

  proc isRsaAvailable*(): bool =
    result = true

  proc generateRsaKeyPair*(bits: int = 4096): RsaKeyPair =
    result.available = false
    result.publicKeyPem = ""
    
    try:
      # OpenSSL 3.0 EVP API
      let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil)
      if ctx.isNil:
        return
      
      if EVP_PKEY_keygen_init(ctx) <= 0:
        EVP_PKEY_CTX_free(ctx)
        return
      
      if EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits.cint) <= 0:
        EVP_PKEY_CTX_free(ctx)
        return
      
      var pkey: ptr EVP_PKEY = nil
      if EVP_PKEY_keygen(ctx, addr pkey) <= 0:
        EVP_PKEY_CTX_free(ctx)
        return
      
      EVP_PKEY_CTX_free(ctx)
      
      result.pkey = pkey
      result.rsa = EVP_PKEY_get1_RSA(pkey)
      
      # Export public key to PEM
      let bio = BIO_new(BIO_s_mem())
      discard PEM_write_bio_RSAPublicKey(bio, result.rsa)
      
      var pemPtr: ptr UncheckedArray[char] = nil
      let pemLen = BIO_get_mem_data(bio, addr pemPtr)
      
      result.publicKeyPem = newString(pemLen)
      copyMem(addr result.publicKeyPem[0], pemPtr, pemLen)
      
      discard BIO_free(bio)
      result.available = true
    except:
      result.available = false
      result.publicKeyPem = ""

  proc rsaPrivateDecrypt*(keyPair: RsaKeyPair, encryptedData: seq[byte]): seq[byte] =
    if not keyPair.available:
      return @[]
    
    try:
      let rsaSize = RSA_size(keyPair.rsa)
      result = newSeq[byte](rsaSize)
      
      let decryptedLen = RSA_private_decrypt(
        encryptedData.len.cint,
        unsafeAddr encryptedData[0],
        addr result[0],
        keyPair.rsa,
        RSA_PKCS1_OAEP_PADDING
      )
      
      if decryptedLen > 0:
        result.setLen(decryptedLen)
      else:
        result = @[]
    except:
      result = @[]

  proc freeRsaKeyPair*(keyPair: var RsaKeyPair) =
    if keyPair.available:
      try:
        if not keyPair.rsa.isNil:
          RSA_free(keyPair.rsa)
          keyPair.rsa = nil
        if not keyPair.pkey.isNil:
          EVP_PKEY_free(keyPair.pkey)
          keyPair.pkey = nil
      except:
        discard
      keyPair.available = false

else:
  # No RSA support
  type
    RsaKeyPair* = object
      publicKeyPem*: string
      available*: bool

  proc isRsaAvailable*(): bool =
    result = false

  proc generateRsaKeyPair*(bits: int = 4096): RsaKeyPair =
    result.available = false
    result.publicKeyPem = ""

  proc rsaPrivateDecrypt*(keyPair: RsaKeyPair, encryptedData: seq[byte]): seq[byte] =
    return @[]

  proc freeRsaKeyPair*(keyPair: var RsaKeyPair) =
    keyPair.available = false
