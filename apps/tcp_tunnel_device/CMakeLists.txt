set(src
  src/tcp_tunnel_main.cpp
  src/tcp_tunnel.cpp
  src/tcp_tunnel_default_policies.cpp
  src/tcp_tunnel_persisting.cpp
  )

add_executable(tcp_tunnel_device "${src}")
target_link_libraries(tcp_tunnel_device nabto_device 3rdparty_tinycbor 3rdparty_json 3rdparty_cxxopts device_examples_common iam_cpp fingerprint_iam)
