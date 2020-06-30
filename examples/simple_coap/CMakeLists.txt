set(src
  src/simple_coap.c
  src/device_event_handler.c
  )

add_executable(simple_coap_device "${src}")
target_link_libraries(simple_coap_device nabto_device)
