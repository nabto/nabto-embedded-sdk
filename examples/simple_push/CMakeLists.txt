set(src
  simple_push_device.c
  )

add_executable(simple_push_device "${src}")
target_link_libraries(simple_push_device nabto_device_static apps_common)

install(TARGETS simple_push_device
  RUNTIME DESTINATION bin
  )
