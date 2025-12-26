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

proc getConfig*(): Config =
  ## Get configuration from compile-time environment variables
  result.uuid = static: getEnv("UUID", "")
  result.profile = static: getEnv("PROFILE", "")
  result.callbackHost = static: getEnv("CALLBACK_HOST", "")
  result.callbackPort = static: getEnv("CALLBACK_PORT", "")
  result.postUri = static: getEnv("POST_URI", "")
  result.userAgent = static: getEnv("USER_AGENT", "")
  result.headers = static: getEnv("HEADERS", "")
  result.proxyHost = static: getEnv("PROXY_HOST", "")
  result.proxyPort = static: getEnv("PROXY_PORT", "")
  result.proxyUser = static: getEnv("PROXY_USER", "")
  result.proxyPass = static: getEnv("PROXY_PASS", "")
  result.aesKey = static: getEnv("AESPSK", "")
  
  let eec = static: getEnv("ENCRYPTED_EXCHANGE_CHECK", "")
  result.encryptedExchange = eec.toLowerAscii in ["true", "t"]
  
  result.callbackInterval = static: parseInt(getEnv("CALLBACK_INTERVAL", ""))
  result.callbackJitter = static: parseInt(getEnv("CALLBACK_JITTER", ""))
  result.killdate = static: getEnv("KILLDATE", "")
  