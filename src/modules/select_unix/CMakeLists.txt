set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(select_unix_src
  ${src_dir}/nm_select_unix.c
  ${src_dir}/nm_select_unix_udp.c
  )

add_library( nm_select_unix STATIC "${select_unix_src}")

target_link_libraries(nm_select_unix np_platform nc_core nm_logging nm_unix_communication_buffer)
