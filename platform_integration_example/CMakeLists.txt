find_package( Threads )

project(select_unix_platform)

set(src
  select_unix_platform.c
  ../src/api/unix/nabto_device_threads_unix.c
  )

add_library(nabto_device_select_unix SHARED "${src}")

target_link_libraries(nabto_device_select_unix nabto_device_api)

target_compile_definitions(nabto_device_select_unix PRIVATE NABTO_DEVICE_API_EXPORTS)
target_compile_definitions(nabto_device_select_unix PRIVATE NABTO_DEVICE_API_SHARED)

target_link_libraries( nabto_device_select_unix
  nm_dtls_cli
  nc_core
  nm_logging_api
  nm_dtls_srv
  np_platform
  nm_mdns
  nm_tcp_tunnel)

target_link_libraries( nabto_device_select_unix ${CMAKE_THREAD_LIBS_INIT} )
