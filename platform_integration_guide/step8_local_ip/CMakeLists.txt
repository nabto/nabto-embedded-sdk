project(step8_localip)
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

  # The event queue used for this platform is based on nabto_device_threads.h thread abstraction.
  ../../src/modules/event_queue/thread_event_queue.c
  ../../src/modules/event_queue/nm_event_queue.c

  # The dns module used for this platform is the unix dns module.
  ../../src/modules/dns/unix/nm_unix_dns.c

  # This integration uses the select based networking module
  ../../src/modules/select_unix/nm_select_unix.c
  ../../src/modules/select_unix/nm_select_unix_udp.c
  ../../src/modules/select_unix/nm_select_unix_tcp.c

  # This integration uses the unix module for getting the local ips on the system.
  ../../src/modules/unix/nm_unix_local_ip.c

  # And our test program of the simplest possible platform integration.
  local_ip_test.c
  )

add_executable(local_ip_test ${src})

target_link_libraries(local_ip_test pthread)
target_include_directories(local_ip_test PRIVATE ${ne_priv_include_dirs})
target_compile_definitions(local_ip_test PRIVATE -DMBEDTLS_CONFIG_FILE=<nabto_mbedtls_config.h>)
