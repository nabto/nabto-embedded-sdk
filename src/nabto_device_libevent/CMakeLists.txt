find_package( Threads )

include_directories(${EVENT__INCLUDE_DIRS})

set(src
  nabto_platform_libevent.c
  libevent_event_queue.c
  )


if (HAVE_PTHREAD_H)
  add_library(nabto_device_threads STATIC ../api/unix/nabto_device_threads_unix.c)
elseif(HAVE_WINDOWS_H)
  add_library(nabto_device_threads STATIC ../api/windows/nabto_device_threads_win.c)
else()
  message(error "missing thread library")
endif()


add_library(libevent_platform STATIC "${src}")
target_link_libraries(libevent_platform
  nm_mdns
  nm_dtls_srv
  nm_dtls_cli
  )

add_library( nabto_device_static STATIC "dummy.c")
target_compile_definitions(nabto_device_static PRIVATE NABTO_DEVICE_WIN32_API_STATIC)
target_compile_definitions(nabto_device_static PUBLIC NABTO_DEVICE_WIN32_API_STATIC)

target_link_libraries(nabto_device_static
  nabto_device_api
  nm_dtls_cli
  nc_core
  nm_logging_api
  nm_dtls_srv
  np_platform
  nm_mdns
  nm_tcp_tunnel
  libevent_platform
  nabto_device_threads
  )


add_library( nabto_device SHARED "dummy.c")

target_compile_definitions(nabto_device PRIVATE NABTO_DEVICE_API_EXPORTS)
target_compile_definitions(nabto_device PRIVATE NABTO_DEVICE_API_SHARED)

target_link_libraries( nabto_device
  nabto_device_api
  nm_dtls_cli
  nc_core
  nm_logging_api
  nm_dtls_srv
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

#set (CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libnabto_device.version")
#set_target_properties(nabto_device PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libnabto_device.version)

install(TARGETS nabto_device
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include/nabto
  )
