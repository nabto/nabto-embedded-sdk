set(src
  nm_unix_mdns.c
  nm_unix_local_ip.c
  )

add_library(nm_unix ${src})
target_link_libraries(nm_unix np_platform)
