set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(src
  ${src_dir}/nc_connection.c
  )


add_library( nc_core STATIC "${src}")
