set(src
  # we have cheated a bit and used an already existing implementation
  # of the threads interface.
  ../../src/modules/threads/unix/nabto_device_threads_unix.c

  # Test program for the threads interface
  ../../src/api_test/nabto_device_test_threads.c

  # Needed utility function to run the test.
  ../../src/api/nabto_device_error.c
  )

add_executable(step1_test ${src} step1_test.c)

target_link_libraries(step1_test pthread)
