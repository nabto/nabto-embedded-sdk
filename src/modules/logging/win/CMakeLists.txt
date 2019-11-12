set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(win_src
  ${src_dir}/nm_win_logging.c
  )


add_library( nm_logging_win STATIC ${win_src})
