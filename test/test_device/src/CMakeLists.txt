set(src
  gopt/gopt.c
  test_device.c
  )

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(test_device ${src})
