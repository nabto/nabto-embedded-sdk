set(src
  nm_logging_test.c
  )

add_library(nm_logging_test "${src}")
target_link_libraries(nm_logging_test PRIVATE np_platform nabto_device_threads)
