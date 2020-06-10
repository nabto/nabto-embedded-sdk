include(${CMAKE_CURRENT_SOURCE_DIR}/../../nabto_primary_files.cmake)
set(src
  ${ne_required_src}

  ${ne_api_test_src}
  # And the threads implmentation from step 1
  ../../src/modules/threads/unix/nabto_device_threads_unix.c

  # And a platform integration
  platform_integration.c

  # And our test program of the simplest possible platform integration.
  logging_test.c
  )

add_executable(logging_test ${src})

target_link_libraries(logging_test pthread)
target_include_directories(logging_test PRIVATE ${ne_priv_include_dirs})
target_compile_definitions(logging_test PRIVATE -DMBEDTLS_CONFIG_FILE=<nabto_mbedtls_config.h>)
