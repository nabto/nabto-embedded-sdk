find_package( Threads )

include_directories(${EVENT__INCLUDE_DIRS})

set(src
  nabto_platform_libevent.c
  libevent_event_queue.c
  )

set(api_src_dir
  ${CMAKE_CURRENT_SOURCE_DIR}/../api/
  )

set(api_src
  ${api_src_dir}/nabto_device.c
  ${api_src_dir}/nabto_device_stream.c
  ${api_src_dir}/nabto_device_coap.c
  ${api_src_dir}/nabto_device_future.c
  ${api_src_dir}/nabto_device_event_handler.c
  ${api_src_dir}/nabto_device_future_queue.c
  ${api_src_dir}/nabto_device_error.c
  ${api_src_dir}/nabto_device_util.c
  ${api_src_dir}/nabto_device_experimental.c
  ${api_src_dir}/nabto_device_connection_events.c
  ${api_src_dir}/nabto_device_events.c
  ${api_src_dir}/nabto_device_authorization.c
  ${api_src_dir}/nabto_device_authorization_events.c
  ${api_src_dir}/nabto_device_tcp_tunnelling.c
  ${api_src_dir}/nabto_device_logging.c
  ${api_src_dir}/nabto_device_integration.c
  )

if (HAVE_PTHREAD_H)
  add_library(nabto_device_threads STATIC ../modules/threads/unix/nabto_device_threads_unix.c)
elseif(HAVE_WINDOWS_H)
  add_library(nabto_device_threads STATIC ../modules/threads/windows/nabto_device_threads_win.c)
else()
  message(error "missing thread library")
endif()


add_library(libevent_platform STATIC "${src}" "${api_src}")
target_link_libraries(libevent_platform
  nm_mdns
  nm_mbedtls_srv
  nm_mbedtls_cli
  nm_mbedtls_random
  nc_core
  np_platform
  nm_mbedtls_srv
  nm_tcp_tunnel
  3rdparty_mbedtls
  )

add_library( nabto_device_static STATIC "dummy.c")
target_compile_definitions(nabto_device_static PRIVATE NABTO_DEVICE_WIN32_API_STATIC)
target_compile_definitions(nabto_device_static PUBLIC NABTO_DEVICE_WIN32_API_STATIC)

target_link_libraries(nabto_device_static
  #nabto_device_api
  nm_mbedtls_cli
  nc_core
  nm_mbedtls_srv
  nm_mbedtls_random
  np_platform
  nm_mdns
  nm_tcp_tunnel
  libevent_platform
  nabto_device_threads
  nc_core
  np_platform
  nm_mbedtls_srv
  nm_tcp_tunnel
  3rdparty_mbedtls
  )


add_library( nabto_device SHARED "dummy.c")

target_compile_definitions(nabto_device PRIVATE NABTO_DEVICE_API_EXPORTS)
target_compile_definitions(nabto_device PRIVATE NABTO_DEVICE_API_SHARED)

target_link_libraries( nabto_device
  nabto_device_api
  nm_mbedtls_cli
  nc_core
  nm_mbedtls_srv
  nm_mbedtls_random
  np_platform
  nm_mdns
  nm_tcp_tunnel
  libevent_platform
  nabto_device_threads
  )

target_link_libraries( nabto_device ${CMAKE_THREAD_LIBS_INIT} )

target_link_libraries(nabto_device nm_libevent event_core)

if (HAVE_WINDOWS_H)
  target_link_libraries(nabto_device ws2_32)
endif()

set_target_properties(nabto_device PROPERTIES PUBLIC_HEADER "../../include/nabto/nabto_device.h;../../include/nabto/nabto_device_experimental.h")

install(TARGETS nabto_device
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include/nabto
  )
