set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(unix_src
  ${src_dir}/nm_unix_communication_buffer.c
  )


add_library( nabto_unix_communication_buffer STATIC ${unix_src})
