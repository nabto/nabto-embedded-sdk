set(src
  simple_coap_device.c
  )

add_executable(simple_coap_device "${src}")
target_link_libraries(simple_coap_device nabto_device apps_common nm_fs_posix)

install(TARGETS simple_coap_device
  RUNTIME DESTINATION bin
  )
