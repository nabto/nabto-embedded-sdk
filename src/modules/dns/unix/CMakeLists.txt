set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(unix_src
  ${src_dir}/nm_unix_dns.c
  )


add_library( nm_unix_dns STATIC ${unix_src})
target_link_libraries( nm_unix_dns pthread nn)
