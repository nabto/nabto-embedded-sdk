
cmake_minimum_required(VERSION 3.2)

project(select_unix_platform)

set(src
  select_unix_platform.c
  select_unix_event_queue.c
  )



set(api_src_dir
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/api
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

add_library(nabto_device_select_unix SHARED ${src} ${api_src})

target_compile_definitions(nabto_device_select_unix PRIVATE NABTO_DEVICE_API_EXPORTS)
target_compile_definitions(nabto_device_select_unix PRIVATE NABTO_DEVICE_API_SHARED)

target_link_libraries( nabto_device_select_unix
  nm_mbedtls_cli
  nm_mbedtls_srv
  nm_mbedtls_random
  nm_event_queue
  nm_select_unix
  nm_mdns
  nm_unix_timestamp
  nm_unix_dns
  nm_communication_buffer
  nc_core
  np_platform
  nm_mbedtls_srv
  nm_tcp_tunnel
  3rdparty_mbedtls
  nabto_device_api
  nm_threads_unix
  )
