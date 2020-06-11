set(src
  nm_mdns_server.c
  )

add_library(nm_mdns ${src})

target_link_libraries(nm_mdns mdns_server np_platform)
