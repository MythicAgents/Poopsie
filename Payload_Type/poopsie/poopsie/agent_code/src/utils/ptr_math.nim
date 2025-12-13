# Pointer arithmetic helpers
# Enables pointer + int operations

template `+`*[T](p: ptr T, offset: int): ptr T =
  cast[ptr T](cast[uint](p) + cast[uint](offset * sizeof(T)))

template `-`*[T](p: ptr T, offset: int): ptr T =
  cast[ptr T](cast[uint](p) - cast[uint](offset * sizeof(T)))

template `+=`*[T](p: var ptr T, offset: int) =
  p = p + offset

template `-=`*[T](p: var ptr T, offset: int) =
  p = p - offset
