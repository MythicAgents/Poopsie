## HTTP client wrapper that uses native OS APIs when possible
## 
## Windows: Custom WinHTTP implementation with full proxy support - no OpenSSL needed for HTTPS
## Linux: Uses std/httpclient with -d:ssl for HTTPS support

when defined(windows):
  # Windows: Custom WinHTTP implementation for full control
  import winim/lean
  import winim/inc/winhttp
  import std/[tables, strutils, parseutils, uri]
  
  type
    HttpHeaders* = ref object
      table*: Table[string, seq[string]]
    
    HttpClientWrapper* = ref object
      headers*: HttpHeaders
      proxyUrl*: string  # Empty = no proxy, otherwise proxy URL
      debug*: bool
  
  # WinHTTP constants not in winim/lean
  const
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
    WINHTTP_ACCESS_TYPE_NO_PROXY = 1
    WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4
    
    WINHTTP_FLAG_SECURE = 0x00800000
    WINHTTP_ADDREQ_FLAG_ADD = 0x20000000
    WINHTTP_ADDREQ_FLAG_REPLACE = 0x80000000'i32
    
    WINHTTP_OPTION_SECURITY_FLAGS = 31
    SECURITY_FLAG_IGNORE_UNKNOWN_CA = 0x00000100
    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE = 0x00000200
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID = 0x00001000
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID = 0x00002000
  
  proc newHttpHeaders*(headers: openArray[(string, string)]): HttpHeaders =
    result = HttpHeaders(table: initTable[string, seq[string]]())
    for (k, v) in headers:
      if not result.table.hasKey(k):
        result.table[k] = @[]
      result.table[k].add(v)
  
  proc `[]=`*(headers: var HttpHeaders, key, val: string) =
    if not headers.table.hasKey(key):
      headers.table[key] = @[]
    headers.table[key].add(val)
  
  proc newClientWrapper*(debug: bool = false): HttpClientWrapper =
    result = HttpClientWrapper()
    result.headers = HttpHeaders(table: initTable[string, seq[string]]())
    result.proxyUrl = ""
    result.debug = debug
  
  proc newClientWrapperWithProxy*(proxyUrl: string, debug: bool = false): HttpClientWrapper =
    result = HttpClientWrapper()
    result.headers = HttpHeaders(table: initTable[string, seq[string]]())
    result.proxyUrl = proxyUrl
    result.debug = debug
  
  proc postContent*(client: HttpClientWrapper, url: string, body: string): string =
    ## Send HTTP POST request using native WinHTTP API with proxy support
    var
      hSession: HINTERNET = nil
      hConnect: HINTERNET = nil
      hRequest: HINTERNET = nil
    
    try:
      # Parse URL
      let parsedUrl = parseUri(url)
      let isHttps = parsedUrl.scheme == "https"
      let port = if parsedUrl.port != "": parseInt(parsedUrl.port) 
                 else: (if isHttps: 443 else: 80)
      
      if client.debug:
        echo "[HTTP_CLIENT] Using WinHTTP for: ", url
        if client.proxyUrl.len > 0:
          echo "[HTTP_CLIENT] Proxy: ", client.proxyUrl
      
      # Open session with proxy support
      var dwAccessType: DWORD
      var lpszProxy: LPCWSTR = nil
      
      if client.proxyUrl.len > 0:
        dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY
        lpszProxy = newWideCString(client.proxyUrl)
      else:
        dwAccessType = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
      
      hSession = WinHttpOpen(
        newWideCString("Mozilla/5.0"),
        dwAccessType,
        lpszProxy,
        nil,
        0
      )
      
      if hSession == nil:
        if client.debug:
          echo "[HTTP_CLIENT] WinHttpOpen failed: ", GetLastError()
        return ""
      
      # Set timeouts (60 seconds)
      discard WinHttpSetTimeouts(hSession, 60000, 60000, 60000, 60000)
      
      # Connect to server
      let hostWide = newWideCString(parsedUrl.hostname)
      hConnect = WinHttpConnect(hSession, cast[LPCWSTR](addr hostWide[0]), 
                                 INTERNET_PORT(port), 0)
      if hConnect == nil:
        if client.debug:
          echo "[HTTP_CLIENT] WinHttpConnect failed: ", GetLastError()
        return ""
      
      # Open request
      let pathWide = newWideCString(parsedUrl.path & 
                                    (if parsedUrl.query.len > 0: "?" & parsedUrl.query else: ""))
      let methodWide = newWideCString("POST")
      
      var dwFlags: DWORD = 0
      if isHttps:
        dwFlags = dwFlags or WINHTTP_FLAG_SECURE
      
      hRequest = WinHttpOpenRequest(hConnect, 
                                     cast[LPCWSTR](addr methodWide[0]),
                                     cast[LPCWSTR](addr pathWide[0]),
                                     nil, nil, nil, dwFlags)
      if hRequest == nil:
        if client.debug:
          echo "[HTTP_CLIENT] WinHttpOpenRequest failed: ", GetLastError()
        return ""
      
      # Disable certificate validation for self-signed certs BEFORE sending
      if isHttps:
        var secFlags: DWORD = SECURITY_FLAG_IGNORE_UNKNOWN_CA or
                              SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE or
                              SECURITY_FLAG_IGNORE_CERT_CN_INVALID or
                              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
        if WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                           addr secFlags, DWORD(sizeof(secFlags))) == 0:
          if client.debug:
            echo "[HTTP_CLIENT] Warning: Failed to disable cert validation: ", GetLastError()
      
      # Add headers
      for key, values in client.headers.table.pairs:
        if values.len > 0:
          let headerLine = key & ": " & values[values.len - 1] & "\r\n"
          let headerWide = newWideCString(headerLine)
          if client.debug:
            echo "[HTTP_CLIENT]   ", key, ": ", values[values.len - 1]
          
          discard WinHttpAddRequestHeaders(hRequest,
            cast[LPCWSTR](addr headerWide[0]), DWORD(-1),
            WINHTTP_ADDREQ_FLAG_ADD or WINHTTP_ADDREQ_FLAG_REPLACE)
      
      # Send request
      let bodyLen = DWORD(body.len)
      let sendResult = WinHttpSendRequest(hRequest, nil, 0, 
                                         if body.len > 0: unsafeAddr body[0] else: nil,
                                         bodyLen, bodyLen, 0)
      if client.debug:
        echo "[HTTP_CLIENT] WinHttpSendRequest result: ", sendResult
      
      if sendResult == 0:
        if client.debug:
          echo "[HTTP_CLIENT] WinHttpSendRequest failed: ", GetLastError()
        return ""
      
      # Receive response
      let recvResult = WinHttpReceiveResponse(hRequest, nil)
      if client.debug:
        echo "[HTTP_CLIENT] WinHttpReceiveResponse result: ", recvResult
      
      if recvResult == 0:
        let recvError = GetLastError()
        if client.debug:
          echo "[HTTP_CLIENT] WinHttpReceiveResponse failed with error: ", recvError
          if recvError == 0:
            echo "[HTTP_CLIENT] Error was 0, checking if connection was closed"
        return ""
      
      # Get status code
      var statusCode: DWORD = 0
      var statusCodeSize = DWORD(sizeof(statusCode))
      discard WinHttpQueryHeaders(hRequest, 
        DWORD(19 or 0x20000000), # WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER
        nil, addr statusCode, addr statusCodeSize, nil)
      
      # Get Content-Length
      var contentLength: DWORD = 0
      var contentLengthSize = DWORD(sizeof(contentLength))
      let hasContentLength = WinHttpQueryHeaders(hRequest,
        DWORD(5 or 0x20000000), # WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER  
        nil, addr contentLength, addr contentLengthSize, nil)
      
      if client.debug:
        echo "[HTTP_CLIENT] Response code: ", statusCode
        if hasContentLength != 0:
          echo "[HTTP_CLIENT] Content-Length: ", contentLength
        else:
          echo "[HTTP_CLIENT] Content-Length: not present or invalid"
      
      # Check if status code is success (2xx)
      if statusCode < 200 or statusCode >= 300:
        if client.debug:
          echo "[HTTP_CLIENT] Non-success status code: ", statusCode
        raise newException(IOError, "HTTP request failed with status code: " & $statusCode)
      
      # Read response body
      result = ""
      var totalRead = 0
      
      if client.debug:
        echo "[HTTP_CLIENT] Starting to read response body..."
      
      while true:
        # Check how much data is available
        var bytesAvailable: DWORD = 0
        if WinHttpQueryDataAvailable(hRequest, addr bytesAvailable) == 0:
          if client.debug:
            echo "[HTTP_CLIENT] WinHttpQueryDataAvailable failed: ", GetLastError()
          break
        
        if client.debug:
          echo "[HTTP_CLIENT] Bytes available: ", bytesAvailable
        
        if bytesAvailable == 0:
          break
        
        # Read the available data
        var buffer = newString(bytesAvailable)
        var bytesRead: DWORD = 0
        
        if WinHttpReadData(hRequest, addr buffer[0], bytesAvailable, addr bytesRead) == 0:
          if client.debug:
            echo "[HTTP_CLIENT] WinHttpReadData failed: ", GetLastError()
          break
        
        if client.debug:
          echo "[HTTP_CLIENT] Read ", bytesRead, " bytes"
        
        if bytesRead > 0:
          result.add(buffer[0..<bytesRead])
          totalRead += int(bytesRead)
      
      if client.debug:
        echo "[HTTP_CLIENT] Total response body length: ", totalRead, " bytes"
    
    except IOError as e:
      # HTTP errors (non-2xx status codes) - re-raise to caller after cleanup
      if client.debug:
        echo "[HTTP_CLIENT] HTTP error: ", e.msg
      raise
    except CatchableError as e:
      # Other errors - log and return empty
      if client.debug:
        echo "[HTTP_CLIENT] Exception: ", e.msg
      result = ""
    finally:
      # Always cleanup handles
      if hRequest != nil:
        WinHttpCloseHandle(hRequest)
      if hConnect != nil:
        WinHttpCloseHandle(hConnect)
      if hSession != nil:
        WinHttpCloseHandle(hSession)

else:
  # Linux: Use standard httpclient with SSL
  import std/httpclient
  
  type
    HttpClientWrapper* = HttpClient
    HttpHeaders* = httpclient.HttpHeaders
  
  proc newHttpHeaders*(headers: openArray[(string, string)]): HttpHeaders =
    result = httpclient.newHttpHeaders(headers)
  
  proc `[]=`*(headers: HttpHeaders, key, val: string) =
    headers[key] = val
  
  proc newClientWrapper*(debug: bool = false): HttpClientWrapper =
    result = httpclient.newHttpClient()
  
  proc newClientWrapperWithProxy*(proxyUrl: string, debug: bool = false): HttpClientWrapper =
    let proxy = httpclient.newProxy(proxyUrl)
    result = httpclient.newHttpClient(proxy = proxy)
  
  proc postContent*(client: HttpClientWrapper, url: string, body: string): string =
    result = httpclient.postContent(client, url, body)
