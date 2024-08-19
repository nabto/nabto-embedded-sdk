set(src
    simple_tunnel_device.c
)

add_executable(simple_tunnel_device "${src}")
target_link_libraries(simple_tunnel_device nabto_device apps_common nm_fs_posix)

install(TARGETS simple_tunnel_device
  RUNTIME DESTINATION bin
  )
