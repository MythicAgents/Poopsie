import std/[strutils, os]

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
    debug*: bool

proc getConfig*(): Config =
  ## Get configuration from compile-time environment variables
  result.uuid = static: getEnv("UUID", "00000000-0000-0000-0000-000000000000")
  result.profile = static: getEnv("PROFILE", "http")
  result.callbackHost = static: getEnv("CALLBACK_HOST", "127.0.0.1")
  result.callbackPort = static: getEnv("CALLBACK_PORT", "80")
  result.postUri = static: getEnv("POST_URI", "data")
  result.userAgent = static: getEnv("USER_AGENT", "Mozilla/5.0")
  result.headers = static: getEnv("HEADERS", "")
  result.proxyHost = static: getEnv("PROXY_HOST", "")
  result.proxyPort = static: getEnv("PROXY_PORT", "")
  result.proxyUser = static: getEnv("PROXY_USER", "")
  result.proxyPass = static: getEnv("PROXY_PASS", "")
  result.aesKey = static: getEnv("AESPSK", "")
  
  let eec = static: getEnv("ENCRYPTED_EXCHANGE_CHECK", "true")
  result.encryptedExchange = eec.toLowerAscii in ["true", "t"]
  
  result.callbackInterval = static: parseInt(getEnv("CALLBACK_INTERVAL", "10"))
  result.callbackJitter = static: parseInt(getEnv("CALLBACK_JITTER", "10"))
  result.killdate = static: getEnv("KILLDATE", "2099-12-31")
  
  let debugStr = static: getEnv("DEBUG", "false")
  result.debug = debugStr.toLowerAscii in ["true", "t"]
