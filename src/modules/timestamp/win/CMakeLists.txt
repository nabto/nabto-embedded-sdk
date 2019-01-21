set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(win_src
  ${src_dir}/nm_win_timestamp.c
  )


add_library( nm_win_timestamp STATIC ${win_src})
