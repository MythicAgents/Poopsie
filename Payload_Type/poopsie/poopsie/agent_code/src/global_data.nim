## Global data storage for agent configuration
## Stores dynamic configuration like spawnto paths for process injection

import std/[locks, json, sequtils]

when defined(windows):
  type
    ImportedScript* = object
      name*: string
      content*: string

    GlobalData* = object
      spawntoX64*: string
      spawntoX64Args*: string
      spawntoX86*: string
      spawntoX86Args*: string
      ppid*: uint32
      importedPsScripts*: seq[ImportedScript]

  var
    globalDataLock: Lock
    globalData: GlobalData

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
    ## Add or replace an imported PowerShell script
    withLock globalDataLock:
      # Replace if script with same name already exists
      var found = false
      for i in 0..<globalData.importedPsScripts.len:
        if globalData.importedPsScripts[i].name == name:
          globalData.importedPsScripts[i].content = content
          found = true
          break
      if not found:
        globalData.importedPsScripts.add(ImportedScript(name: name, content: content))

  proc getImportedPsScripts*(): seq[ImportedScript] =
    ## Get all imported PowerShell scripts
    withLock globalDataLock:
      return globalData.importedPsScripts

  proc getImportedPsScriptNames*(): seq[string] =
    ## Get the names of all imported PowerShell scripts
    withLock globalDataLock:
      return globalData.importedPsScripts.mapIt(it.name)

  proc clearImportedPsScripts*() =
    ## Clear all imported PowerShell scripts
    withLock globalDataLock:
      globalData.importedPsScripts = @[]

  proc getGlobalDataJson*(): string =
    ## Get global data as JSON string for config command
    withLock globalDataLock:
      let scriptNames = globalData.importedPsScripts.mapIt(it.name)
      let data = %*{
        "spawnto_x64": globalData.spawntoX64,
        "spawnto_x64_arguments": globalData.spawntoX64Args,
        "spawnto_x86": globalData.spawntoX86,
        "spawnto_x86_arguments": globalData.spawntoX86Args,
        "ppid": globalData.ppid,
        "imported_ps_scripts": scriptNames
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
    discard

  proc getGlobalDataJson*(): string =
    ## Get global data as JSON string (empty on Linux)
    return "{}"
