set(src
  src/tcp_tunnel_main.cpp
  src/tcp_tunnel.cpp
  src/tcp_tunnel_default_policies.cpp
  src/tcp_tunnel_default_policies.c
  src/tcp_tunnel_persisting.cpp
  )

set(csrc
  src/tcp_tunnel_main.c
  )

add_executable(tcp_tunnel_device "${src}")
target_link_libraries(tcp_tunnel_device nabto_device 3rdparty_tinycbor 3rdparty_json 3rdparty_cxxopts device_examples_common iam_cpp fingerprint_iam 3rdparty_cjson nm_policies nm_iam apps_common)


add_executable(tcp_tunnel_device_c "${csrc}")
target_link_libraries(tcp_tunnel_device_c nabto_device 3rdparty_gopt)
