set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(src
  ${src_dir}/nc_connection.c
  ${src_dir}/nc_attacher.c
  ${src_dir}/nc_packet.c
  ${src_dir}/nc_keep_alive.c
  ${src_dir}/nc_client_connect.c
  )

set(test_src
  ${src_dir}/nc_attacher_test.c
  ${src_dir}/nc_connection_test.c
  ${src_dir}/nc_tests.c
  )

add_library( nc_core STATIC "${src}")

add_library( nc_core_test STATIC "${test_src}")
