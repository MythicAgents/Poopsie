## RSA utilities for key exchange with Mythic C2
## 
## Windows: OpenSSL 3.5.4 statically linked (no runtime DLL dependencies)
## Linux: Dynamic linking to system OpenSSL (requires libssl.so)

import std/[base64, strutils]

# OpenSSL declarations for both static (Windows) and dynamic (Linux) linking
when defined(staticOpenSSL):
  # Windows: Static linking handled by builder.py (architecture-specific paths)
  # No need to specify link directives here - builder.py adds them based on x64/x86
  
  # Declare OpenSSL types and functions directly (no dynlib)
  type
    BIGNUM {.importc: "struct bignum_st", header: "<openssl/bn.h>", incompleteStruct.} = object
    RSA {.importc: "struct rsa_st", header: "<openssl/rsa.h>", incompleteStruct.} = object
    BIO {.importc: "struct bio_st", header: "<openssl/bio.h>", incompleteStruct.} = object
    BIO_METHOD {.importc: "struct bio_method_st", header: "<openssl/bio.h>", incompleteStruct.} = object
    EVP_PKEY {.importc: "struct evp_pkey_st", header: "<openssl/evp.h>", incompleteStruct.} = object
    EVP_PKEY_CTX {.importc: "struct evp_pkey_ctx_st", header: "<openssl/evp.h>", incompleteStruct.} = object
  
  const
    RSA_F4 = 65537'u64
    RSA_PKCS1_OAEP_PADDING = 4
    BIO_NOCLOSE = 0
    EVP_PKEY_RSA = 6
  
  # OpenSSL 3.0 API functions
  proc BN_new(): ptr BIGNUM {.cdecl, importc, header: "<openssl/bn.h>".}
  proc BN_free(a: ptr BIGNUM) {.cdecl, importc, header: "<openssl/bn.h>".}
  proc BN_set_word(a: ptr BIGNUM, w: uint64): cint {.cdecl, importc, header: "<openssl/bn.h>".}
  
  proc EVP_PKEY_new(): ptr EVP_PKEY {.cdecl, importc, header: "<openssl/evp.h>".}
  proc EVP_PKEY_free(pkey: ptr EVP_PKEY) {.cdecl, importc, header: "<openssl/evp.h>".}
  proc EVP_PKEY_CTX_new_id(id: cint, e: pointer): ptr EVP_PKEY_CTX {.cdecl, importc, header: "<openssl/evp.h>".}
  proc EVP_PKEY_CTX_free(ctx: ptr EVP_PKEY_CTX) {.cdecl, importc, header: "<openssl/evp.h>".}
  proc EVP_PKEY_keygen_init(ctx: ptr EVP_PKEY_CTX): cint {.cdecl, importc, header: "<openssl/evp.h>".}
  proc EVP_PKEY_CTX_set_rsa_keygen_bits(ctx: ptr EVP_PKEY_CTX, mbits: cint): cint {.cdecl, importc, header: "<openssl/evp.h>".}
  proc EVP_PKEY_keygen(ctx: ptr EVP_PKEY_CTX, ppkey: ptr ptr EVP_PKEY): cint {.cdecl, importc, header: "<openssl/evp.h>".}
  proc EVP_PKEY_get1_RSA(pkey: ptr EVP_PKEY): ptr RSA {.cdecl, importc, header: "<openssl/evp.h>".}
  
  proc RSA_free(r: ptr RSA) {.cdecl, importc, header: "<openssl/rsa.h>".}
  proc RSA_size(rsa: ptr RSA): cint {.cdecl, importc, header: "<openssl/rsa.h>".}
  proc RSA_private_decrypt(flen: cint, `from`: ptr byte, to: ptr byte, 
                           rsa: ptr RSA, padding: cint): cint {.cdecl, importc, header: "<openssl/rsa.h>".}
  
  proc BIO_new(typ: ptr BIO_METHOD): ptr BIO {.cdecl, importc, header: "<openssl/bio.h>".}
  proc BIO_free(a: ptr BIO): cint {.cdecl, importc, header: "<openssl/bio.h>".}
  proc BIO_s_mem(): ptr BIO_METHOD {.cdecl, importc, header: "<openssl/bio.h>".}
  proc BIO_ctrl(bp: ptr BIO, cmd: cint, larg: clong, parg: pointer): clong {.cdecl, importc, header: "<openssl/bio.h>".}
  proc BIO_read(b: ptr BIO, data: pointer, dlen: cint): cint {.cdecl, importc, header: "<openssl/bio.h>".}
  
  proc PEM_write_bio_RSAPublicKey(bp: ptr BIO, x: ptr RSA): cint {.cdecl, importc, header: "<openssl/pem.h>".}
  
  template BIO_get_mem_data(b: ptr BIO, pp: untyped): clong =
    BIO_ctrl(b, 3, 0, pp)

elif defined(ssl):
  # Linux: Dynamic linking to system OpenSSL (libssl.so)
  import openssl
  
  # Type aliases for compatibility with static linking code
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
  
  proc PEM_write_bio_RSAPublicKey(bp: ptr BIO, x: ptr RSA): cint {.cdecl, dynlib: DLLSSLName, importc.}
  
  template BIO_get_mem_data(b: ptr BIO, pp: untyped): clong =
    BIO_ctrl(b, 3, 0, pp)

type
  RsaKeyPair* = object
    when defined(staticOpenSSL) or defined(ssl):
      pkey: ptr EVP_PKEY
      rsa: ptr RSA
    publicKeyPem*: string
    available*: bool

proc isRsaAvailable*(): bool =
  ## Check if RSA functionality is available
  when defined(staticOpenSSL) or defined(ssl):
    result = true  # Available with both static and dynamic linking
  else:
    result = false

proc generateRsaKeyPair*(bits: int = 4096): RsaKeyPair =
  ## Generate an RSA key pair for key exchange
  ## Default is 4096 bits to match oopsie
  ## Returns empty/unavailable result if OpenSSL is not available
  
  when not defined(staticOpenSSL) and not defined(ssl):
    result.available = false
    return
  
  try:
    when defined(staticOpenSSL) or defined(ssl):
      # Initialize result first to avoid uninitialized memory
      result.available = false
      result.publicKeyPem = ""
      
      # OpenSSL 3.0 EVP API (same for both static and dynamic)
      let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil)
      if ctx.isNil:
        result.available = false
        return
      
      if EVP_PKEY_keygen_init(ctx) <= 0:
        EVP_PKEY_CTX_free(ctx)
        result.available = false
        return
      
      if EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits.cint) <= 0:
        EVP_PKEY_CTX_free(ctx)
        result.available = false
        return
      
      var pkey: ptr EVP_PKEY = nil
      if EVP_PKEY_keygen(ctx, addr pkey) <= 0:
        EVP_PKEY_CTX_free(ctx)
        result.available = false
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
  ## Decrypt data using RSA private key with OAEP padding
  if not keyPair.available:
    return @[]
  
  when not defined(staticOpenSSL) and not defined(ssl):
    return @[]
  
  try:
    when defined(staticOpenSSL) or defined(ssl):
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
  ## Free the RSA key pair resources
  
  when not defined(staticOpenSSL) and not defined(ssl):
    return
  
  if keyPair.available:
    try:
      when defined(staticOpenSSL) or defined(ssl):
        if not keyPair.rsa.isNil:
          RSA_free(keyPair.rsa)
          keyPair.rsa = nil
        if not keyPair.pkey.isNil:
          EVP_PKEY_free(keyPair.pkey)
          keyPair.pkey = nil
    except:
      discard
  keyPair.available = false
