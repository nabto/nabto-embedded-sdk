set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(epoll_src
  ${src_dir}/nm_epoll.c
  )

set(epoll_test_src
    ${src_dir}/nm_epoll_test.c
    ${src_dir}/nm_epoll.c
  )


add_library( nm_epoll STATIC ${epoll_src})

add_executable(nm_epoll_test "${epoll_test_src}")

target_link_libraries(nm_epoll_test np_platform nc_core nm_logging nm_unix_communication_buffer nm_unix_timestamp)

target_link_libraries(nm_epoll np_platform nc_core nm_logging nm_unix_communication_buffer)
