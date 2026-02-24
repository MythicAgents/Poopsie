import json, strutils
import ../utils/[strenc, m_responses, debug]
import ../global_data

type
  DeregisterFileArgs = object
    action: string
    name: string

proc deregisterFile*(taskId: string, params: JsonNode): JsonNode =
  ## Manage the file cache - remove, list, or clear cached files
  try:
    let args = to(params, DeregisterFileArgs)

    case args.action
    of obf("remove"):
      if args.name.len == 0:
        return mythicError(taskId, obf("File name is required for remove action"))
      if removeCachedFile(args.name):
        return mythicSuccess(taskId, obf("File '") & args.name & obf("' removed from cache"))
      else:
        return mythicError(taskId, obf("File '") & args.name & obf("' not found in cache"))

    of obf("list"):
      let files = getCachedFileInfo()
      if files.len == 0:
        return mythicSuccess(taskId, obf("File cache is empty"))

      var output = obf("Cached files:\n")
      output.add(alignLeft(obf("Name"), 30) & alignLeft(obf("Size"), 15) & "\n")
      output.add(alignLeft(obf("----"), 30) & alignLeft(obf("----"), 15) & "\n")
      for info in files:
        let sizeStr = if info.size > 1024 * 1024:
          formatFloat(info.size.float / (1024.0 * 1024.0), ffDecimal, 2) & obf(" MB")
        elif info.size > 1024:
          formatFloat(info.size.float / 1024.0, ffDecimal, 2) & obf(" KB")
        else:
          $info.size & obf(" B")
        output.add(alignLeft(info.name, 30) & alignLeft(sizeStr, 15) & "\n")
      return mythicSuccess(taskId, output)

    of obf("clear"):
      let files = getCachedFileInfo()
      let count = files.len
      clearFileCache()
      return mythicSuccess(taskId, obf("Cleared ") & $count & obf(" files from cache"))

    else:
      return mythicError(taskId, obf("Unknown action: '") & args.action & "'")

  except Exception as e:
    return mythicError(taskId, obf("deregister_file error: ") & e.msg)
