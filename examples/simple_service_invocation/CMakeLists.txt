set(src
  simple_service_invocation_device.c
  )

add_executable(simple_service_invocation "${src}")
target_link_libraries(simple_service_invocation nabto_device_static apps_common nm_fs_unix)

install(TARGETS simple_service_invocation
  RUNTIME DESTINATION bin
  )
