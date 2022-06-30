find_package( Threads )

include_directories(${EVENT__INCLUDE_DIRS})

set(src
  nabto_platform_libevent.c
  libevent_event_queue.c
  )

if (HAVE_PTHREAD_H)
  add_library(nabto_device_threads STATIC ../modules/threads/unix/nabto_device_threads_unix.c)
elseif(HAVE_WINDOWS_H)
  add_library(nabto_device_threads STATIC ../modules/threads/windows/nabto_device_threads_win.c)
else()
  message(error "missing thread library")
endif()

target_link_libraries(nabto_device_threads PUBLIC nn)

add_library( nabto_device_static STATIC "${src}" "${ne_api_src}" "${ne_api_future_queue_src}" "${ne_api_test_src}")
target_compile_definitions(nabto_device_static PRIVATE NABTO_DEVICE_WIN32_API_STATIC)
target_compile_definitions(nabto_device_static PUBLIC NABTO_DEVICE_WIN32_API_STATIC)

target_link_libraries(nabto_device_static
  nc_core
  np_platform
  nm_mdns
  nm_tcp_tunnel
  nm_logging_api
  nabto_device_threads
  )

if (NABTO_USE_MBEDTLS)
  target_link_libraries(nabto_device_static
    nm_mbedtls_srv
    nm_mbedtls_cli
    nm_mbedtls_random
    nm_mbedtls_spake2
    3rdparty_mbedtls
  )
endif()
if(NABTO_USE_WOLFSSL)
  target_link_libraries(nabto_device_static
    nm_wolfssl_srv
    nm_wolfssl_cli
    nm_wolfssl_random
  )
endif()

target_link_libraries( nabto_device_static ${CMAKE_THREAD_LIBS_INIT} )

target_link_libraries(nabto_device_static nm_libevent event_core)


add_library( nabto_device SHARED "${src}" "${ne_api_src}" "${ne_api_future_queue_src}" "${ne_api_test_src}")

target_compile_definitions(nabto_device PRIVATE NABTO_DEVICE_API_EXPORTS)
target_compile_definitions(nabto_device PRIVATE NABTO_DEVICE_API_SHARED)

target_link_libraries( nabto_device
  nc_core
  np_platform
  nm_mdns
  nm_tcp_tunnel
  nm_logging_api
  nabto_device_threads
  )

if (NABTO_USE_MBEDTLS)
  target_link_libraries(nabto_device
    nm_mbedtls_srv
    nm_mbedtls_cli
    nm_mbedtls_random
    nm_mbedtls_spake2
  )
endif()
if(NABTO_USE_WOLFSSL)
  target_link_libraries(nabto_device
    nm_wolfssl_srv
    nm_wolfssl_cli
    nm_wolfssl_random
  )
endif()

target_link_libraries( nabto_device ${CMAKE_THREAD_LIBS_INIT} )

target_link_libraries(nabto_device nm_libevent event_core)

if (HAVE_WINDOWS_H)
  target_link_libraries(nabto_device ws2_32)
  target_link_libraries(nabto_device_static ws2_32)
endif()

set_target_properties(nabto_device PROPERTIES PUBLIC_HEADER "../../include/nabto/nabto_device.h;../../include/nabto/nabto_device_experimental.h")

install(TARGETS nabto_device
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  PUBLIC_HEADER DESTINATION include/nabto
  )

set(integration_test_src
    nabto_device_libevent_integration_test.cpp
  )

if (DEVICE_BUILD_TESTS)
  add_executable(nabto_device_libevent_integration_test ${integration_test_src})
  target_include_directories(nabto_device_libevent_integration_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../test_cpp)
  target_link_libraries(nabto_device_libevent_integration_test nabto_device_static test_util)
endif()
