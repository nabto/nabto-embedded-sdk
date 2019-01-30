set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(unix_src
  ${src_dir}/nm_unix_timestamp.c
  )


add_library( nm_timestamp STATIC ${unix_src})
