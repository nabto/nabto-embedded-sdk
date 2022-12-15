set(src
  simple_stream_tunnel_device.c
  )

add_executable(simple_stream_tunnel_device "${src}")
target_link_libraries(simple_stream_tunnel_device nabto_device_static apps_common)

install(TARGETS simple_stream_tunnel_device
  RUNTIME DESTINATION bin
  )
