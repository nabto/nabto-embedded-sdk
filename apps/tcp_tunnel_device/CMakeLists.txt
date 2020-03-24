set(csrc
  src/tcp_tunnel_main.c
  src/iam_config.c
  src/tcp_tunnel_state.c
  src/tcp_tunnel_services.c
  src/device_event_handler.c
  )

add_executable(tcp_tunnel_device "${csrc}")
target_link_libraries(tcp_tunnel_device nabto_device 3rdparty_gopt apps_common nm_iam)
