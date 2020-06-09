# Step 2 is a bit more complex regarding files needed. First we make a library called nabto_device_step2, which we then use in our test program


set(src
  ${ne_required_src}

  ${ne_api_test_src}
  # And the threads implmentation from step 1
  ../../src/modules/threads/unix/nabto_device_threads_unix.c

  # And a platform integration
  platform_integration_step2.c

  # And our test program of the simplest possible platform integration.
  step2_test.c
  )

add_executable(step2_test ${src})

target_link_libraries(step2_test pthread)
target_include_directories(step2_test PRIVATE ${ne_priv_include_dirs})
target_compile_definitions(step2_test PRIVATE -DMBEDTLS_CONFIG_FILE=<nabto_mbedtls_config.h>)
