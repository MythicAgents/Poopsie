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

proc getConfig*(): Config =
  ## Get configuration from compile-time environment variables
  result.uuid = static: getEnv(obf("UUID"), "")
  result.profile = static: getEnv(obf("PROFILE"), "")
  result.callbackHost = static: getEnv(obf("CALLBACK_HOST"), "")
  result.callbackPort = static: getEnv(obf("CALLBACK_PORT"), "")
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
  
  result.callbackInterval = static: parseInt(getEnv(obf("CALLBACK_INTERVAL"), ""))
  result.callbackJitter = static: parseInt(getEnv(obf("CALLBACK_JITTER"), ""))
  result.killdate = static: getEnv(obf("KILLDATE"), "")
  