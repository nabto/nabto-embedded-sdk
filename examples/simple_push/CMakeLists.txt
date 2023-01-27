set(src
  ${ne_iam_src}
  simple_push_device.c
  )

add_executable(simple_push_device "${src}")
target_link_libraries(simple_push_device nabto_device_static apps_common nm_fs_unix)

install(TARGETS simple_push_device
  RUNTIME DESTINATION bin
  )
