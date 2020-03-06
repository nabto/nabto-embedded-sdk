set(src
  nm_tcp_tunnel.c
  nm_tcp_tunnel_coap.c
  nm_tcp_tunnel_connection.c
  )

add_library(nm_tcp_tunnel "${src}")
target_link_libraries(nm_tcp_tunnel nc_core)
