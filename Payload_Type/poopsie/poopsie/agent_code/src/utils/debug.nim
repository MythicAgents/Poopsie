template debug*(data: varargs[string, `$`]) =
  when not defined(release):
    echo data
