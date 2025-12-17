## Registry Query - Query registry keys and values

import std/[json, strformat, strutils]
import ../config
import ../utils/mythic_responses

when defined(windows):
  import winim/lean
  
  const
    KEY_READ = 0x20019
    REG_SZ = 1
    REG_DWORD = 4
    REG_BINARY = 3
    ERROR_NO_MORE_ITEMS = 259
  
  type
    RegQueryResult = object
      hive: string
      name: string
      full_name: string
      value: string
      value_type: string
      result_type: string
  
  proc RegOpenKeyExW(hKey: HKEY, lpSubKey: LPCWSTR, ulOptions: DWORD, 
                     samDesired: DWORD, phkResult: ptr HKEY): LONG 
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc RegEnumKeyExW(hKey: HKEY, dwIndex: DWORD, lpName: LPWSTR, 
                     lpcchName: ptr DWORD, lpReserved: ptr DWORD,
                     lpClass: LPWSTR, lpcchClass: ptr DWORD, 
                     lpftLastWriteTime: ptr FILETIME): LONG 
    {.importc, dynlib: "advapi32.dll", stdcall.}
  
  proc RegEnumValueW(hKey: HKEY, dwIndex: DWORD, lpValueName: LPWSTR, 
                     lpcchValueName: ptr DWORD, lpReserved: ptr DWORD,
                     lpType: ptr DWORD, lpData: ptr BYTE, lpcbData: ptr DWORD): LONG 
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

proc regQuery*(taskId: string, params: JsonNode): JsonNode =
  ## Query registry keys and values
  let cfg = getConfig()
  
  when defined(windows):
    try:
      # Parse parameters
      let hive = params["hive"].getStr()
      let key = params["key"].getStr()
      
      if cfg.debug:
        echo &"[DEBUG] reg_query: hive={hive}, key={key}"
      
      let hiveHandle = getHiveHandle(hive)
      if hiveHandle == cast[HKEY](0):
        return mythicError(taskId, "Invalid hive specified")
      
      let keyNameW = newWideCString(key)
      var keyHandle: HKEY = cast[HKEY](0)
      
      let status = RegOpenKeyExW(hiveHandle, keyNameW, 0, KEY_READ, addr keyHandle)
      if status != 0:
        return mythicError(taskId, &"Failed to open registry key: {status}")
      
      var results: seq[RegQueryResult] = @[]
      
      # Enumerate subkeys
      var index: DWORD = 0
      while true:
        var subkeyName = newSeq[WCHAR](256)
        var subkeyNameLen: DWORD = 256
        
        let enumStatus = RegEnumKeyExW(
          keyHandle,
          index,
          cast[LPWSTR](addr subkeyName[0]),
          addr subkeyNameLen,
          nil,
          nil,
          nil,
          nil
        )
        
        if enumStatus == ERROR_NO_MORE_ITEMS:
          break
        elif enumStatus != 0:
          discard RegCloseKey(keyHandle)
          return mythicError(taskId, &"Failed to enumerate subkeys: {enumStatus}")
        
        let subkeyNameStr = $cast[WideCString](addr subkeyName[0])
        results.add(RegQueryResult(
          hive: hive,
          name: subkeyNameStr,
          full_name: &"{key}\\{subkeyNameStr}",
          value: "",
          value_type: "",
          result_type: "key"
        ))
        
        index += 1
      
      # Enumerate values
      index = 0
      while true:
        var valueName = newSeq[WCHAR](256)
        var valueNameLen: DWORD = 256
        var valueData = newSeq[byte](1024)
        var valueDataLen: DWORD = 1024
        var valueType: DWORD = 0
        
        let enumStatus = RegEnumValueW(
          keyHandle,
          index,
          cast[LPWSTR](addr valueName[0]),
          addr valueNameLen,
          nil,
          addr valueType,
          cast[ptr BYTE](addr valueData[0]),
          addr valueDataLen
        )
        
        if enumStatus == ERROR_NO_MORE_ITEMS:
          break
        elif enumStatus != 0:
          discard RegCloseKey(keyHandle)
          return mythicError(taskId, &"Failed to enumerate values: {enumStatus}")
        
        let valueNameStr = $cast[WideCString](addr valueName[0])
        
        # Parse value based on type
        var valueStr = ""
        var valueTypeStr = ""
        
        case valueType
        of REG_SZ:
          # String value (UTF-16)
          if valueDataLen > 0:
            valueStr = $cast[WideCString](addr valueData[0])
          valueTypeStr = "string"
        of REG_DWORD:
          # DWORD value
          if valueDataLen >= 4:
            let dwordVal = cast[ptr uint32](addr valueData[0])[]
            valueStr = $dwordVal
          valueTypeStr = "dword"
        of REG_BINARY:
          # Binary value - show as hex bytes
          var hexStr = ""
          for i in 0..<min(valueDataLen.int, valueData.len):
            if i > 0:
              hexStr.add(" ")
            hexStr.add(&"{valueData[i]:02X}")
          valueStr = hexStr
          valueTypeStr = "binary"
        else:
          valueStr = "Unsupported value type"
          valueTypeStr = "unknown"
        
        results.add(RegQueryResult(
          hive: hive,
          name: valueNameStr,
          full_name: key,
          value: valueStr,
          value_type: valueTypeStr,
          result_type: "value"
        ))
        
        index += 1
      
      discard RegCloseKey(keyHandle)
      
      # Convert results to JSON
      var resultsJson = newJArray()
      for result in results:
        resultsJson.add(%*{
          "hive": result.hive,
          "name": result.name,
          "full_name": result.full_name,
          "value": result.value,
          "value_type": result.value_type,
          "result_type": result.result_type
        })
      
      return mythicSuccess(taskId, $resultsJson)
      
    except Exception as e:
      return mythicError(taskId, &"reg_query error: {e.msg}")
  else:
    return mythicError(taskId, "reg_query command is only available on Windows")
