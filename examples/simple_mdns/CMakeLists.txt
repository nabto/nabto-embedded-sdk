set(src
  simple_mdns_device.c
  )

add_executable(simple_mdns_device "${src}")
target_link_libraries(simple_mdns_device nabto_device apps_common)

install(TARGETS simple_mdns_device
  RUNTIME DESTINATION bin
  )
