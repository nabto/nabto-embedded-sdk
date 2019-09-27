set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(src
  ${src_dir}/np_ip_address.c
  ${src_dir}/np_platform.c
  ${src_dir}/np_logging.c
  ${src_dir}/np_udp.c
  ${src_dir}/np_event_queue.c
  ${src_dir}/np_error_code.c
  ${src_dir}/np_util.c
  )

set(test_src
  ${src_dir}/np_ip_address_test.c
  ${src_dir}/np_platform_test.c
  ${src_dir}/np_logging_test.c
  ${src_dir}/np_event_queue_test.c
  ${src_dir}/np_tests.c
  )

add_library(np_platform STATIC "${src}")

add_library(np_platform_test STATIC "${test_src}")
