set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(win_src
  ${src_dir}/nm_win_dns.c
  )

set(win_test_src
  ${src_dir}/nm_win_dns.c
  ${src_dir}/nm_win_dns_test.c
  )


add_library( nm_dns STATIC ${win_src})

add_executable( nm_dns_test ${win_test_src})

target_link_libraries( nm_dns wsock32 ws2_32 )

target_link_libraries( nm_dns_test np_platform nm_logging_win nm_timestamp wsock32 ws2_32)
