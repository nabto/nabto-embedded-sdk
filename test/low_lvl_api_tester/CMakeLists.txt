set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(ll_api_test_src
  ${src_dir}/main.c
  )

add_executable(ll_api_test "${ll_api_test_src}")

target_link_libraries(ll_api_test
  test_platform
  )
