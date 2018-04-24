set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(src
  ${src_dir}/ip_address.c
  ${src_dir}/nabto_logging.c
  ${src_dir}/platform.c
  )

set(test_src
  ${src_dir}/ip_address_test.c
  ${src_dir}/nabto_logging_test.c
  ${src_dir}/platform_test.c
  )

add_library(nabto_platform STATIC "${src}")

add_library(nabto_platform_test STATIC "${test_src}")
