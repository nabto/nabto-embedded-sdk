set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(src
  ${src_dir}/nc_connection.c
  ${src_dir}/nc_attacher.c
  ${src_dir}/nc_packet.c
  )


add_library( nc_core STATIC "${src}")
