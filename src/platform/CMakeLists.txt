set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(src
  ${src_dir}/np_ip_address.c
  ${src_dir}/np_logging.c
  ${src_dir}/np_udp.c
  ${src_dir}/np_event_queue.c
  ${src_dir}/np_error_code.c
  ${src_dir}/np_util.c
  ${src_dir}/np_completion_event.c
  ${src_dir}/np_timestamp.c
  )

add_library(np_platform STATIC "${src}")
target_link_libraries(np_platform 3rdparty_nn)
