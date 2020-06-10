
cmake_minimum_required(VERSION 3.2)

project(select_unix_platform)

set(src
  select_unix_platform.c
  )

add_library(nabto_device_select_unix SHARED ${src} ${ne_api_src} ${ne_api_test_src})

target_compile_definitions(nabto_device_select_unix PRIVATE NABTO_DEVICE_API_EXPORTS)
target_compile_definitions(nabto_device_select_unix PRIVATE NABTO_DEVICE_API_SHARED)

target_link_libraries( nabto_device_select_unix
  nc_core
  np_platform
  nm_mbedtls_cli
  nm_mbedtls_srv
  nm_mbedtls_random
  nm_event_queue
  nm_select_unix
  nm_mdns
  nm_unix_timestamp
  nm_unix_dns
  nm_communication_buffer
  nm_tcp_tunnel
  3rdparty_mbedtls
  nm_threads_unix
  )


set(test_src
  select_unix_platform_test.c
  )

add_executable(select_unix_platform_test ${test_src})
target_link_libraries(select_unix_platform_test nabto_device_select_unix)
