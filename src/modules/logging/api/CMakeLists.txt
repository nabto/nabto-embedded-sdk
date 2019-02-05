set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})


if ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
  set(api_log_src
    ${src_dir}/nm_api_logging.c
    ${src_dir}/nm_api_logging_stdout_unix.c
    )
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
  set(api_log_src
    ${src_dir}/nm_api_logging.c
    ${src_dir}/nm_api_logging_stdout_win.c
    )
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  set(api_log_src
    ${src_dir}/nm_api_logging.c
    ${src_dir}/nm_api_logging_stdout_unix.c
    )
endif()



add_library( nm_logging_api STATIC ${api_log_src})
