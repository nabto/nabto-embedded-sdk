find_package( Threads )

if (UNIX)

  set(src
    nabto_device_threads_unix.c
    )

  add_library(nm_threads_unix "${src}")

  target_link_libraries( nm_threads_unix np_platform NabtoCommon::nn ${CMAKE_THREAD_LIBS_INIT} )
endif()
