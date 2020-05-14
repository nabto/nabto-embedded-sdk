if (WIN32)

  set(src nabto_device_threads_win.c)

  add_library(nm_threads_windows "${src}")



endif()
