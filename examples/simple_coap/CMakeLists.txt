set(src
  src/simple_coap.c
  )

add_executable(simple_coap_device "${src}")

install(TARGETS simple_coap_device
  RUNTIME DESTINATION bin
  )

target_link_libraries(simple_coap_device nabto_device)
