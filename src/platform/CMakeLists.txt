set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(src
  ${src_dir}/np_ip_address.c
  ${src_dir}/np_platform.c
  ${src_dir}/np_logging.c
  ${src_dir}/np_udp.c
  ${src_dir}/np_event_queue.c
  ${src_dir}/np_error_code.c
  ${src_dir}/np_util.c
  ${src_dir}/np_vector.c
  ${src_dir}/np_list.c
  ${src_dir}/np_string_map.c
  ${src_dir}/np_string_set.c
  )

add_library(np_platform STATIC "${src}")
