set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(epoll_src
  ${src_dir}/nm_epoll.c
  ${src_dir}/nm_epoll_udp.c
  ${src_dir}/nm_epoll_tcp.c
  )

add_library( nm_epoll STATIC ${epoll_src})

target_link_libraries(nm_epoll np_platform nm_logging nm_unix_communication_buffer)
