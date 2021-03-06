project(step5_event_queue)
cmake_minimum_required(VERSION 3.2)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../nabto_primary_files.cmake)
set(src
  ${ne_required_src}

  ${ne_api_test_src}
  # And the threads implmentation from step 1
  ../../src/modules/threads/unix/nabto_device_threads_unix.c

  # And a platform integration
  platform_integration.c

  # And the timestamp module
  ../../src/modules/timestamp/unix/nm_unix_timestamp.c

  # The event queue used for this module is based on nabto_device_threads.h thread abstraction.
  ../../src/modules/event_queue/thread_event_queue.c
  ../../src/modules/event_queue/nm_event_queue.c

  # And our test program of the simplest possible platform integration.
  event_queue_test.c
  )

add_executable(event_queue_test ${src})

target_link_libraries(event_queue_test pthread)
target_include_directories(event_queue_test PRIVATE ${ne_priv_include_dirs})
target_compile_definitions(event_queue_test PRIVATE -DMBEDTLS_CONFIG_FILE=<nabto_mbedtls_config.h>)
