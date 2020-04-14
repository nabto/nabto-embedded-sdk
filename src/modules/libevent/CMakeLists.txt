find_package(Libevent)

set(src
  nm_libevent_dns.c
  nm_libevent.c
  nm_libevent_udp.c
  nm_libevent_timestamp.c
  )

add_library(nm_libevent ${src})
target_include_directories(nm_libevent PUBLIC ${LIBEVENT_INCLUDE_DIRS})
target_link_libraries(nm_libevent nm_posix nm_posix nm_unix_communication_buffer)
target_link_libraries(nm_libevent ${LIBEVENT_STATIC_LIBRARIES})
