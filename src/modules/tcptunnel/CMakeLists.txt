set(src
  nm_tcptunnel.c
  nm_tcptunnel_coap.c
  nm_tcptunnel_connection.c
  )

add_library(nm_tcptunnel "${src}")
target_link_libraries(nm_tcptunnel nc_core)
