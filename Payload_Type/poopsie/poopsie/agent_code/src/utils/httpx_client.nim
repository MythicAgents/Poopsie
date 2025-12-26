import std/[base64, strutils, json, tables, uri, sequtils]
import http_client
import ../utils/debug

# Transform functions (client-side - encoding)
proc transformBase64(data: seq[byte]): seq[byte] =
  ## Base64 encode
  let encoded = encode(data)
  result = newSeq[byte](encoded.len)
  for i, c in encoded:
    result[i] = byte(c)

proc transformBase64url(data: seq[byte]): seq[byte] =
  ## Base64 URL-safe encode (with padding, matches Java's Base64.getUrlEncoder())
  let encoded = encode(data)
  var urlSafe = encoded.replace("+", "-").replace("/", "_")  # Keep padding =
  result = newSeq[byte](urlSafe.len)
  for i, c in urlSafe:
    result[i] = byte(c)

proc transformXor(data: seq[byte], key: string): seq[byte] =
  ## XOR with key
  if key.len == 0:
    return data
  result = newSeq[byte](data.len)
  for i in 0..<data.len:
    result[i] = data[i] xor byte(key[i mod key.len])

proc transformPrepend(data: seq[byte], value: string): seq[byte] =
  ## Prepend value to data
  result = newSeq[byte](value.len + data.len)
  for i, c in value:
    result[i] = byte(c)
  for i, b in data:
    result[value.len + i] = b

proc transformAppend(data: seq[byte], value: string): seq[byte] =
  ## Append value to data
  result = newSeq[byte](data.len + value.len)
  for i, b in data:
    result[i] = b
  for i, c in value:
    result[data.len + i] = byte(c)

proc transformNetbios(data: seq[byte]): seq[byte] =
  ## NetBIOS encoding (lowercase)
  result = newSeq[byte](data.len * 2)
  for i, b in data:
    let left = ((b and 0xF0) shr 4) + 0x61
    let right = (b and 0x0F) + 0x61
    result[i * 2] = left
    result[i * 2 + 1] = right

proc transformNetbiosu(data: seq[byte]): seq[byte] =
  ## NetBIOS encoding (uppercase)
  result = newSeq[byte](data.len * 2)
  for i, b in data:
    let left = ((b and 0xF0) shr 4) + 0x41
    let right = (b and 0x0F) + 0x41
    result[i * 2] = left
    result[i * 2 + 1] = right

# Transform functions (server-side - decoding - reverse order)
proc transformBase64Reverse(data: seq[byte]): seq[byte] =
  ## Base64 decode
  try:
    let decoded = decode(cast[string](data))
    result = cast[seq[byte]](decoded)
  except:
    result = @[]

proc transformBase64urlReverse(data: seq[byte]): seq[byte] =
  ## Base64 URL-safe decode
  try:
    var encoded = cast[string](data)
    # Restore standard base64 format
    encoded = encoded.replace("-", "+").replace("_", "/")
    # Add padding if needed
    while encoded.len mod 4 != 0:
      encoded.add('=')
    let decoded = decode(encoded)
    result = cast[seq[byte]](decoded)
  except:
    result = @[]

proc transformXorReverse(data: seq[byte], key: string): seq[byte] =
  ## XOR is reversible (same operation)
  result = transformXor(data, key)

proc transformPrependReverse(data: seq[byte], value: string): seq[byte] =
  ## Remove prepended value
  if data.len < value.len:
    return @[]
  result = data[value.len..^1]

proc transformAppendReverse(data: seq[byte], value: string): seq[byte] =
  ## Remove appended value
  if data.len < value.len:
    return @[]
  result = data[0..<(data.len - value.len)]

proc transformNetbiosReverse(data: seq[byte]): seq[byte] =
  ## NetBIOS decoding (lowercase)
  if data.len mod 2 != 0:
    return @[]
  result = newSeq[byte](data.len div 2)
  for i in 0..<result.len:
    let left = (data[i * 2] - 0x61) shl 4
    let right = data[i * 2 + 1] - 0x61
    result[i] = left or right

proc transformNetbiosuReverse(data: seq[byte]): seq[byte] =
  ## NetBIOS decoding (uppercase)
  if data.len mod 2 != 0:
    return @[]
  result = newSeq[byte](data.len div 2)
  for i in 0..<result.len:
    let left = (data[i * 2] - 0x41) shl 4
    let right = data[i * 2 + 1] - 0x41
    result[i] = left or right

proc applyClientTransforms(data: string, transforms: JsonNode): seq[byte] =
  ## Apply client transforms in order
  result = cast[seq[byte]](data)
  
  if transforms.isNil or transforms.kind != JArray:
    return result
  
  for transform in transforms:
    if not transform.hasKey("action"):
      continue
    
    let action = transform["action"].getStr()
    let value = if transform.hasKey("value"): transform["value"].getStr() else: ""
    
    debug "[DEBUG] Applying client transform: ", action
    
    case action
    of "base64":
      result = transformBase64(result)
    of "base64url":
      result = transformBase64url(result)
    of "xor":
      result = transformXor(result, value)
    of "prepend":
      result = transformPrepend(result, value)
    of "append":
      result = transformAppend(result, value)
    of "netbios":
      result = transformNetbios(result)
    of "netbiosu":
      result = transformNetbiosu(result)
    else:
      debug "[DEBUG] Unknown transform: ", action

proc applyServerTransforms(data: seq[byte], transforms: JsonNode): seq[byte] =
  ## Apply server transforms in reverse order
  result = data
  
  if transforms.isNil or transforms.kind != JArray or transforms.len == 0:
    return result
  
  # Apply transforms in reverse order
  for i in countdown(transforms.len - 1, 0):
    let transform = transforms[i]
    if not transform.hasKey("action"):
      continue
    
    let action = transform["action"].getStr()
    let value = if transform.hasKey("value"): transform["value"].getStr() else: ""
    
    debug "[DEBUG] Applying server transform (reverse): ", action
    
    case action
    of "base64":
      result = transformBase64Reverse(result)
    of "base64url":
      result = transformBase64urlReverse(result)
    of "xor":
      result = transformXorReverse(result, value)
    of "prepend":
      result = transformPrependReverse(result, value)
    of "append":
      result = transformAppendReverse(result, value)
    of "netbios":
      result = transformNetbiosReverse(result)
    of "netbiosu":
      result = transformNetbiosuReverse(result)
    else:
      debug "[DEBUG] Unknown server transform: ", action

proc httpxPost*(url: string, body: string, postConfig: JsonNode): string =
  ## Make HTTP POST request using raw_c2_config with transforms and message locations
  
  var requestData = cast[seq[byte]](body)
  
  # Apply client transforms if present
  if postConfig.hasKey("client") and postConfig["client"].hasKey("transforms"):
    requestData = applyClientTransforms(body, postConfig["client"]["transforms"])
    debug "[DEBUG] Request data after transforms: ", requestData.len, " bytes"
  
  # Create HTTP client using our custom wrapper (WinHTTP on Windows, httpclient on Linux)
  var client = newClientWrapper()
  
  # Add client headers if present
  if postConfig.hasKey("client") and postConfig["client"].hasKey("headers"):
    let headers = postConfig["client"]["headers"]
    for key, val in headers.pairs:
      client.headers[key] = val.getStr()
      debug "[DEBUG] Request header: ", key, ": ", val.getStr()
  
  # Prepare request based on message location
  var responseBody: string
  
  if postConfig.hasKey("client") and postConfig["client"].hasKey("message"):
    let message = postConfig["client"]["message"]
    let location = message["location"].getStr()
    let name = message["name"].getStr()
    
    case location
    of "cookie":
      # Add as cookie
      let cookieValue = name & "=" & cast[string](requestData)
      client.headers["Cookie"] = cookieValue
      debug "[DEBUG] Request location: cookie (", name, ")"
      responseBody = client.postContent(url, "")
    
    of "header":
      # Add as header
      client.headers[name] = cast[string](requestData)
      debug "[DEBUG] Request location: header (", name, ")"
      responseBody = client.postContent(url, "")
    
    else: # body or default
      debug "[DEBUG] Request location: body"
      responseBody = client.postContent(url, cast[string](requestData))
  else:
    # Default: send as body
    debug "[DEBUG] Request location: body (default)"
    responseBody = client.postContent(url, cast[string](requestData))
  
  debug "[DEBUG] Response received: ", responseBody.len, " bytes"
  
  # NOTE: Message locations for responses (cookie, header) are not currently supported
  # because our http_client wrapper only returns the body. This matches the HTTP profile
  # behavior and is sufficient for most use cases. The client can send via cookie/header
  # but responses are always from body.
  var responseData = cast[seq[byte]](responseBody)
  
  # Apply server transforms if present
  if postConfig.hasKey("server") and postConfig["server"].hasKey("transforms"):
    responseData = applyServerTransforms(responseData, postConfig["server"]["transforms"])
    debug "[DEBUG] Response data after reverse transforms: ", responseData.len, " bytes"
  
  result = cast[string](responseData)
