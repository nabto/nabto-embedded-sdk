set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(select_win_src
  ${src_dir}/nm_select_win.c
  )

set(select_win_test_src
    ${src_dir}/nm_select_win_test.c
    ${src_dir}/nm_select_win.c
  )


add_library( nm_udp STATIC ${select_win_src})

#add_executable(nm_select_win_test "${select_win_test_src}")

#target_link_libraries(nm_select_win_test np_platform nc_core nm_logging nm_unix_communication_buffer nm_timestamp)

target_link_libraries(nm_udp np_platform nc_core nm_logging nm_unix_communication_buffer)
