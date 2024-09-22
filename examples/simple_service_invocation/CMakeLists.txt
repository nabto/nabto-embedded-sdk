set(src
  simple_service_invocation_device.c
  )

add_executable(simple_service_invocation "${src}")
target_link_libraries(simple_service_invocation nabto_device apps_common nm_fs_posix)

install(TARGETS simple_service_invocation
  RUNTIME DESTINATION bin
  )
