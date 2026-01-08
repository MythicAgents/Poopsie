# Package

version       = "0.1.0"
author        = "poopsie"
description   = "Mythic C2 Agent in Nim"
license       = "MIT"
srcDir        = "src"
bin           = @["poopsie"]

# Dependencies

requires "nim >= 2.2.0"
requires "nimcrypto >= 0.6.0"
requires "winim >= 3.9.2"
requires "pixie >= 5.0.6"
requires "ws >= 0.5.0"