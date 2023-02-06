set(src
  simple_password_authentication_device.c
  )

add_executable(simple_password_authentication_device "${src}")
target_link_libraries(simple_password_authentication_device nabto_device_static apps_common nm_fs_posix)

install(TARGETS simple_password_authentication_device
  RUNTIME DESTINATION bin
  )
