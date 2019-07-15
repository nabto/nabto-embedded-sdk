set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(access_control_src
  nm_iam.c
  nm_iam_parse.c
  nm_iam_util.c
  nm_iam_coap.c
  nm_iam_cbor.c
  )

set(test_src
  nm_iam_parse_test.c
  nm_iam_tests.c
  nm_iam_test.c
  )

add_library( nm_access_control STATIC ${access_control_src})

target_link_libraries(nm_access_control np_platform 3rdparty_cjson 3rdparty_tinycbor)


add_library(nm_access_control_test ${test_src})
target_link_libraries(nm_access_control_test nm_access_control)
