set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(unix_src
  ${src_dir}/nm_unix_logging.c
  )


add_library( nm_logging STATIC ${unix_src})
