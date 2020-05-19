set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})


set(api_log_src
  ${src_dir}/nm_api_logging.c
  ${src_dir}/nm_api_logging_stdout.c
  )

add_library( nm_logging_api STATIC ${api_log_src})
