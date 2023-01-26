set(src
  simple_stream_device.c
  )

add_executable(simple_stream_device "${src}")
target_link_libraries(simple_stream_device nabto_device_static apps_common nm_file_unix)

install(TARGETS simple_stream_device
  RUNTIME DESTINATION bin
  )
