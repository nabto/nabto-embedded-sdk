set(csrc
  ${ne_iam_src}
  src/tcp_tunnel_main.c
  src/iam_config.c
  src/tcp_tunnel_state.c
  src/tcp_tunnel_services.c
  src/tcp_tunnel_init.c
  src/device_event_handler.c
  src/help.c
  src/echo_stream.c
  )

add_executable(stream_tunnel_app_device "${csrc}")
target_link_libraries(stream_tunnel_app_device nabto_device_static 3rdparty_gopt apps_common)

install(TARGETS stream_tunnel_app_device
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include/nabto
  )
