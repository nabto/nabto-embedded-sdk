project(select_unix_platform)

set(src
  select_unix_platform.c
  select_unix_event_queue.c
  )

add_library(select_unix_platform ${src})

target_link_libraries(select_unix_platform
  nm_dtls_cli
  nm_dtls_srv
  nm_event_queue
  nm_select_unix
  nm_mdns
  )

add_library(nabto_device_select_unix SHARED dummy.c)

target_compile_definitions(nabto_device_select_unix PRIVATE NABTO_DEVICE_API_EXPORTS)
target_compile_definitions(nabto_device_select_unix PRIVATE NABTO_DEVICE_API_SHARED)

target_link_libraries( nabto_device_select_unix
  nabto_device_api
  nm_threads_unix
  select_unix_platform
  )
