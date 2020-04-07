set(src
  nm_libevent_dns.c
  nm_libevent.c
  )

add_library(nm_libevent ${src})

target_link_libraries(nm_libevent event)
