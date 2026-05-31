template debug*(data: varargs[string, `$`]) =
  when not defined(release):
    var msg = "[poopsie] "
    for d in data:
      msg.add d
    stderr.writeLine msg

template debugLog*(module: static[string], data: varargs[string, `$`]) =
  when not defined(release):
    var msg = "[poopsie:" & module & "] "
    for d in data:
      msg.add d
    stderr.writeLine msg
