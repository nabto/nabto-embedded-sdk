set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(src
  nm_epoll.c
  nm_epoll_udp.c
  nm_epoll_tcp.c
  nm_epoll_mdns_udp_bind.c
  nm_epoll_event_queue.c
  nm_epoll_timestamp.c
  )

add_library( nm_epoll STATIC "${src}")

target_link_libraries(nm_epoll nm_event_queue np_platform)
