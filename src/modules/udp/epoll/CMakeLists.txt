set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(epoll_src
  ${src_dir}/nm_epoll.c
  )


add_library( nabto_epoll STATIC ${epoll_src})

target_link_libraries(nabto_epoll nabto_platform nabto_unix_logging nabto_unix_communication_buffer)
