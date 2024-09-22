set(src
  simple_stream_device.c
  )

add_executable(simple_stream_device "${src}")
target_link_libraries(simple_stream_device nabto_device apps_common nm_fs_posix)

install(TARGETS simple_stream_device
  RUNTIME DESTINATION bin
  )
