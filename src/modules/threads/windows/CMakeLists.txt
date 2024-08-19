find_package(NabtoCommon REQUIRED)
if (WIN32)

  set(src nabto_device_threads_win.c)

  add_library(nm_threads_windows "${src}")
  target_link_libraries(nm_threads_windows PUBLIC NabtoCommon::nn)



endif()
