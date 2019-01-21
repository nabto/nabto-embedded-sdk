set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(win_src
  ${src_dir}/nm_win_dns.c
  )


add_library( nm_dns STATIC ${win_src})
target_link_libraries( nm_dns wsock32 ws2_32 )
