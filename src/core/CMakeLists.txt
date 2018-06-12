set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(src
  ${src_dir}/nc_connection.c
  ${src_dir}/nc_attacher.c
  ${src_dir}/nc_packet.c
  ${src_dir}/nc_keep_alive.c
  ${src_dir}/nc_client_connect.c
  )


add_library( nc_core STATIC "${src}")
