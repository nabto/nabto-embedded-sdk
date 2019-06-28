set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(access_control_src
  nm_access_control.c
  nm_iam_parse.c
  )

set(test_src
  nm_iam_parse_test.c
  nm_access_control_tests.c
  nm_iam_test.c
  )

add_library( nm_access_control STATIC ${access_control_src})

target_link_libraries(nm_access_control np_platform 3rdparty_cjson)


add_library(nm_access_control_test ${test_src})
target_link_libraries(nm_access_control_test nm_access_control)
