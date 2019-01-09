cmake_minimum_required(VERSION 3.0)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(api_test_src
  ${src_dir}/main.c
  )

add_executable(api_test "${api_test_src}")

target_link_libraries(api_test
  nabto_device
  )
