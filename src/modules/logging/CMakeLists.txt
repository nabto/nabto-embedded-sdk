set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(unix_src
  ${src_dir}/unix_logging.c
  )


add_library( nabto_unix_logging STATIC ${unix_src})
