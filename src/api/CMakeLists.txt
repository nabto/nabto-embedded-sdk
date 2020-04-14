set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

find_package( Threads )

set(nabto_device_src
  nabto_device.c
  nabto_device_stream.c
  nabto_device_coap.c
  nabto_device_future.c
  nabto_device_event_handler.c
  nabto_api_future_queue.c
  nabto_device_error.c
  nabto_device_util.c
  nabto_device_experimental.c
  nabto_device_connection_events.c
  nabto_device_events.c
  nabto_device_authorization.c
  nabto_device_authorization_events.c
  nabto_device_tcp_tunnelling.c

  )

find_package(Libevent REQUIRED)

if (Libevent_FOUND)
  list(APPEND nabto_device_src
    ${src_dir}/libevent/nabto_platform_libevent.c
    )
  include_directories(${LIBEVENT_INCLUDE_DIRS})
elseif(HAVE_SYS_EPOLL_H)
  list(APPEND nabto_device_src
    ${src_dir}/unix/nabto_device_platform_modules_linux.c
    nabto_platform.c
    )
else()
  message(FATAL_ERROR "missing platform implemenetation")
endif()

if (HAVE_PTHREAD_H)
  list(APPEND nabto_device_src
    ${src_dir}/unix/nabto_device_threads_unix.c
    )
elseif(HAVE_WINDOWS_H)
  list(APPEND nabto_device_src
    ${src_dir}/windows/nabto_device_threads_win.c
    )
else()
  message(error "missing thread library")
endif()

add_definitions(-DNABTO_DEVICE_API_EXPORTS)
add_library( nabto_device_api "${nabto_device_src}")

target_link_libraries( nabto_device_api
  nm_dtls_cli
  nc_core
  nm_logging_api
  nm_dns
  nm_mdns
  nm_dtls_srv
  np_platform
  nm_tcp_tunnel
  nm_posix
  )

add_library( nabto_device SHARED "${nabto_device_src}")

target_compile_definitions(nabto_device PRIVATE NABTO_DEVICE_API_EXPORTS)
target_compile_definitions(nabto_device PRIVATE NABTO_DEVICE_API_SHARED)

target_link_libraries( nabto_device
  nm_dtls_cli
  nc_core
  nm_logging_api
  nm_dtls_srv
  np_platform
  nm_mdns
  nm_tcp_tunnel
  nm_posix)



target_link_libraries( nabto_device ${CMAKE_THREAD_LIBS_INIT} )

if (Libevent_FOUND)
  target_link_libraries(nabto_device nm_libevent)
elseif(HAVE_EPOLL_H)
  target_link_libraries( nabto_device
    nm_epoll
    nm_dns
    nm_timestamp
    )
endif()

if (HAVE_WINDOWS_H)
  target_link_libraries(nabto_device ws2_32)
endif()

set_target_properties(nabto_device PROPERTIES PUBLIC_HEADER "../../include/nabto/nabto_device.h;../../include/nabto/nabto_device_experimental.h")

#set (CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libnabto_device.version")
#set_target_properties(nabto_device PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libnabto_device.version)

install(TARGETS nabto_device
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include/nabto
  )
