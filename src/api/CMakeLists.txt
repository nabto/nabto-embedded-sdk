set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(nabto_device_src
  nabto_device.c
  nabto_device_stream.c
  nabto_device_coap.c
  nabto_device_future.c
  nabto_device_event_handler.c
  nabto_device_future_queue.c
  nabto_device_error.c
  nabto_device_util.c
  nabto_device_experimental.c
  nabto_device_connection_events.c
  nabto_device_events.c
  nabto_device_authorization.c
  nabto_device_authorization_events.c
  nabto_device_tcp_tunnelling.c
  nabto_device_logging.c
  nabto_device_integration.c
  )

add_library( nabto_device_api "${nabto_device_src}")

target_link_libraries( nabto_device_api
  nc_core
  np_platform
  nm_mbedtls_srv
  nm_tcp_tunnel
  3rdparty_mbedtls
  )
