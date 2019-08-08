set(src
  gopt/gopt.c
  test_device.cpp
  )

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(test_device ${src})
target_link_libraries(test_device nabto_device mbedtls)
