set(src
  nm_libevent_dns.c
  nm_libevent.c
  nm_libevent_udp.c
  nm_libevent_tcp.c
  nm_libevent_timestamp.c
  nm_libevent_get_local_ip.c
  nm_libevent_mdns_udp_bind.c
  )

add_library(nm_libevent ${src})

target_link_libraries(nm_libevent nm_communication_buffer 3rdparty_libevent)
#target_link_libraries(nm_libevent ${LIBEVENT_STATIC_LIBRARIES})
