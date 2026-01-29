# Taken from the excellent NiCOFF project by @frkngksl
# Source: https://github.com/frkngksl/NiCOFF/blob/main/BeaconFunctions.nim

import winim/lean
import ptr_math
import system
import strenc

#[
typedef struct {
    char* original; /* the original buffer [so we can free it] */
    char* buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} datap;
]#

# I directly turned beacon_compatibility.c to Nim. There are some empty functions beacuse the implementations there were not given, and I'm not familiar with these functions.
type
    Datap* {.bycopy,packed.} = object
        original*: ptr char
        buffer*: ptr char
        length*: int
        size*: int
#[
typedef struct {
    char* original; /* the original buffer [so we can free it] */
    char* buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} formatp;
]#
    Formatp* {.bycopy,packed.} = object
        original*: ptr char
        buffer*: ptr char
        length*: int
        size*: int


var bCO:ptr char = nil
var bCS: int = 0
var bCOff: int = 0


# void BDP(datap* parser, char* buffer, int size)
proc BDP(parser:ptr Datap,buffer: ptr char,size:int):void{.stdcall.} =
    if(cast[uint64](parser) == 0):
        return
    parser.original = buffer
    parser.buffer = buffer
    parser.length = size-4
    parser.size = size-4
    parser.buffer += 4
    return

# int     BDI(datap* parser);
proc BDI(parser:ptr Datap):int{.stdcall.} =
    var returnValue:int = 0
    if(parser.length < 4):
        return returnValue
    copyMem(addr(returnValue),parser.buffer,4)
    parser.length-=4
    parser.buffer+=4
    return returnValue

# short   BDS(datap* parser);
proc BDS(parser:ptr Datap):int16{.stdcall.} =
    var returnValue:int16 = 0
    if(parser.length < 2):
        return returnValue
    copyMem(addr(returnValue),parser.buffer,2)
    parser.length-=2
    parser.buffer+=2
    return returnValue

# int     BDL(datap* parser);
proc BDL(parser:ptr Datap):int{.stdcall.} =
    return parser.length

# char* BDE(datap* parser, int* size);
proc BDE(parser:ptr Datap,size:ptr int):ptr char{.stdcall.} =
    var length:int32 = 0
    var outData: ptr char = nil
    if(parser.length < 4):
        return NULL
    copyMem(addr(length),parser.buffer,4)
    parser.buffer += 4
    outData = parser.buffer
    if(outData == NULL):
        return NULL
    parser.length -= 4
    parser.length -= length
    parser.buffer += length
    if(size != NULL and outData != NULL):
        size[] = length
    return outData

# void    BFA(formatp* format, int maxsz);
proc BFA(format:ptr Formatp,maxsz:int):void{.stdcall.} =
    if(format == NULL):
        return
    #format.original = cast[ptr char](HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,maxsz))
    format.original = cast[ptr char](alloc(maxsz))
    var cursorPtr:ptr byte = cast[ptr byte](format.original)
    for i in countup(0,maxsz-1):
        cursorPtr[] = 0x00
        cursorPtr+=1
    format.buffer = format.original
    format.length = 0
    format.size = maxsz

# void    BFR(formatp* format);
proc BFR(format:ptr Formatp):void{.stdcall.} =
    var cursorPtr:ptr byte = cast[ptr byte](format.original)
    for i in countup(0,format.size-1):
        cursorPtr[] = 0x00
        cursorPtr+=1
    format.buffer = format.original
    format.length = format.size

# void    BFF(formatp* format);
proc BFF(format:ptr Formatp):void{.stdcall.} =
    if(format == NULL):
        return
    if(cast[uint64](format.original) != 0):
        dealloc(format.original)
        #HeapFree(GetProcessHeap(),cast[DWORD](NULL),cast[LPVOID](format.original))
        format.original = NULL
    format.buffer = NULL
    format.length = 0
    format.size = 0

# void    BFApp(formatp* format, char* text, int len);
proc BFApp(format:ptr Formatp,text:ptr char,len:int):void{.stdcall.} =
    copyMem(format.buffer,text,len)
    format.buffer+=len
    format.length+=len

# void   BPrF(int type, char* fmt, ...);
# Reference: https://forum.nim-lang.org/t/7352
type va_list* {.importc: obf("va_list"), header: obf("<stdarg.h>").} = object
proc va_start(format: va_list, args: ptr char) {.stdcall, importc, header: obf("stdio.h")}
proc va_end(ap: va_list) {.stdcall, importc, header: obf("stdio.h")}
proc vprintf(format: cstring, args: va_list) {.stdcall, importc, header: obf("stdio.h")}
proc vsnprintf(buffer: cstring; size: int; fmt: cstring; args: va_list): int {.stdcall, importc, dynlib: obf("msvcrt").}

# void    BFP(formatp* format, char* fmt, ...);
proc BFP(format:ptr Formatp,fmt:ptr char):void{.stdcall, varargs.} =
    var length:int = 0
    var args: va_list
    va_start(args, fmt)
    length = vsnprintf(NULL, 0, fmt, args)
    va_end(args)
    if(format.length + length > format.size):
        return
    va_start(args, fmt)
    discard vsnprintf(format.buffer,length,fmt,args)
    va_end(args)
    format.length+=length
    format.buffer+=length

# char* BFTS(formatp* format, int* size);
proc BFTS(format:ptr Formatp,size:ptr int):ptr char{.stdcall.} =
    size[] = format.length
    return format.original


# uint32_t swap_endianess(uint32_t indata);
proc SwapEndianess(indata:uint32):uint32{.stdcall.} =
    var testInt:uint32 = cast[uint32](0xaabbccdd)
    var outInt:uint32 = indata
    if(cast[ptr uint8](unsafeaddr(testInt))[] == 0xdd):
        cast[ptr uint8](unsafeaddr(outInt))[] = (cast[ptr uint8](unsafeaddr(indata))+3)[]
        (cast[ptr uint8](unsafeaddr(outInt))+1)[] = (cast[ptr uint8](unsafeaddr(indata))+2)[]
        (cast[ptr uint8](unsafeaddr(outInt))+2)[] = (cast[ptr uint8](unsafeaddr(indata))+1)[]
        (cast[ptr uint8](unsafeaddr(outInt))+3)[] = cast[ptr uint8](unsafeaddr(indata))[]
    return outint


# void    BFInt(formatp* format, int value);
proc BFInt(format:ptr Formatp,value:int):void{.stdcall.} =
    var indata:uint32 = cast[uint32](value)
    var outdata:uint32 = 0
    if(format.length + 4 > format.size):
        return
    outdata = SwapEndianess(indata)
    copyMem(format.buffer,addr(outdata),4)
    format.length += 4
    format.buffer += 4

const
    CALLBACK_OUTPUT      = 0x0
    CALLBACK_OUTPUT_OEM  = 0x1e
    CALLBACK_ERROR       = 0x0d
    CALLBACK_OUTPUT_UTF8 = 0x20


proc BPrF(typeArg:int,fmt:ptr char):void{.stdcall, varargs.} =
    var length:int = 0
    var tempPtr:ptr char = nil
    var args: va_list
    va_start(args, fmt)
    vprintf(fmt, args)
    va_end(args)

    va_start(args, fmt)
    length = vsnprintf(NULL,0,fmt,args)
    va_end(args)
    tempPtr = cast[ptr char](realloc(bCO,bCS+length+1))
    if(tempPtr == nil):
        return
    bCO = tempPtr
    for i in countup(0,length):
        (bCO + bCOff + i)[] = cast[char](0x00)
    va_start(args, fmt)
    length = vsnprintf(bCO+bCOff,length,fmt,args)
    bCS += length
    bCOff += length
    va_end(args)
    
    
    

#void   BO(int type, char* data, int len);
proc BO(typeArg:int,data:ptr char,len:int):void{.stdcall.} =
    var tempPtr:ptr char = nil
    tempPtr = cast[ptr char](realloc(bCO,bCS + len + 1))
    bCO = tempPtr
    if(tempPtr == nil):
        return
    for i in countup(0,len):
        (bCO + bCOff + i)[] = cast[char](0x00)
    copyMem(bCO+bCOff,data,len)
    bCS += len
    bCOff += len
    #[
        if(beacon_compatibility_output != nil):
        tempPtr = HeapReAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,beacon_compatibility_output,)
    ]#
    
# Token Functions 

# BOOL   BUT(HANDLE token);
proc BUT(token: HANDLE):BOOL{.stdcall.} =
    SetThreadToken(NULL,token)
    return TRUE

# void   BRT();
proc BRT():void{.stdcall.} =
    RevertToSelf()

# BOOL   BIA();
# Not implemented
proc BIA():BOOL{.stdcall.} =
    return FALSE

# Spawn+Inject Functions 
# void   BGST(BOOL x86, char* buffer, int length);
proc BGST(x86: BOOL, buffer:ptr char, length:int):void{.stdcall.} =
    var tempBufferPath:string = ""
    if(cast[uint64](buffer) == 0):
        return 
    if(x86):
        tempBufferPath = obf("C:\\Windows\\SysWOW64\\rundll32.exe")
        if(tempBufferPath.len > length):
            return
        copyMem(buffer,unsafeaddr(tempBufferPath[0]),tempBufferPath.len)
    else:
        tempBufferPath = obf("C:\\Windows\\System32\\rundll32.exe")
        if(tempBufferPath.len > length):
            return
        copyMem(buffer,unsafeaddr(tempBufferPath[0]),tempBufferPath.len)

# BOOL BSTP(BOOL x86, BOOL ignoreToken, STARTUPINFO* sInfo, PROCESS_INFORMATION* pInfo);
proc BSTP(x86: BOOL, ignoreToken:BOOL, sInfo:ptr STARTUPINFOA, pInfo: ptr PROCESS_INFORMATION):BOOL{.stdcall.} =
    var bSuccess:BOOL = FALSE
    if(x86):
        bSuccess = CreateProcessA(NULL,obf("C:\\Windows\\SysWOW64\\rundll32.exe"),NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,sInfo,pInfo)
    else:
        bSuccess = CreateProcessA(NULL,obf("C:\\Windows\\System32\\rundll32.exe"),NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,sInfo,pInfo)
    return bSuccess

# void   BIP(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len);
# Not implemented
proc BIP(hProc: HANDLE, pid:int, payload:ptr char, p_len: int,p_offset: int, arg:ptr char, a_len:int):void{.stdcall.} =
    return

# void   BITP(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len);
# Not implemented
proc BITP(pInfo: ptr PROCESS_INFORMATION, payload:ptr char, p_len: int,p_offset: int, arg:ptr char, a_len:int):void{.stdcall.} =
    return

# void   BCP(PROCESS_INFORMATION* pInfo);
proc BCP(pInfo: ptr PROCESS_INFORMATION):void{.stdcall.} =
    CloseHandle(pInfo.hThread)
    CloseHandle(pInfo.hProcess)

# Utility Functions 
# BOOL   toWideChar(char* src, wchar_t* dst, int max); TODO FIX
# Not implemented
proc toWideChar(src:ptr char,dst: ptr char ,max: int):BOOL{.stdcall.} =
    return FALSE


# char* BGOD(int* outsize);
proc BGOD*(outSize:ptr int):ptr char{.stdcall.} =
    var outData:ptr char = bCO
    if(cast[uint64](outSize) != 0):
        outsize[] = bCS
    bCO = NULL
    bCS = 0
    bCOff = 0
    return outData

var functionAddresses*:array[23,tuple[name: string, address: uint64]] = [
    (obf("BeaconDataParse"), cast[uint64](BDP)),
    (obf("BeaconDataInt"), cast[uint64](BDI)),
    (obf("BeaconDataShort"), cast[uint64](BDS)),
    (obf("BeaconDataLength"), cast[uint64](BDL)),
    (obf("BeaconDataExtract"), cast[uint64](BDE)),
    (obf("BeaconFormatAlloc"), cast[uint64](BFA)),
    (obf("BeaconFormatReset"), cast[uint64](BFR)),
    (obf("BeaconFormatFree"), cast[uint64](BFF)),
    (obf("BeaconFormatAppend"), cast[uint64](BFApp)),
    (obf("BeaconFormatPrintf"), cast[uint64](BFP)),
    (obf("BeaconFormatToString"), cast[uint64](BFTS)),
    (obf("BeaconFormatInt"), cast[uint64](BFInt)),
    (obf("BeaconPrintf"), cast[uint64](BPrF)),
    (obf("BeaconOutput"), cast[uint64](BO)),
    (obf("BeaconUseToken"), cast[uint64](BUT)),
    (obf("BeaconRevertToken"), cast[uint64](BRT)),
    (obf("BeaconIsAdmin"), cast[uint64](BIA)),
    (obf("BeaconGetSpawnTo"), cast[uint64](BGST)),
    (obf("BeaconSpawnTemporaryProcess"), cast[uint64](BSTP)),
    (obf("BeaconInjectProcess"), cast[uint64](BIP)),
    (obf("BeaconInjectTemporaryProcess"), cast[uint64](BITP)),
    (obf("BeaconCleanupProcess"), cast[uint64](BCP)),
    (obf("toWideChar"), cast[uint64](toWideChar))
]