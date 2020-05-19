set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(select_unix_src
  nm_select_unix.c
  nm_select_unix_udp.c
  nm_select_unix_tcp.c
  )

add_library( nm_select_unix STATIC "${select_unix_src}")

target_link_libraries(nm_select_unix nm_unix np_platform nc_core nm_logging_unix nm_unix_communication_buffer)
