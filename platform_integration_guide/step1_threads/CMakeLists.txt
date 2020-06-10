set(src
  # we have cheated a bit and used an already existing implementation
  # of the threads interface.
  ../../src/modules/threads/unix/nabto_device_threads_unix.c

  # Test program for the threads interface
  ../../src/api_test/nabto_device_test_threads.c

  # Needed utility function to run the test.
  ../../src/api/nabto_device_error.c

  threads_test.c
  )

include_directories(../../include)
include_directories(../../src)

add_executable(threads_test ${src})

target_link_libraries(threads_test pthread)
