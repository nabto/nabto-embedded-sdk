set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(access_control_src
  ${src_dir}/nm_access_control.c
  )

add_library( nm_access_control STATIC ${access_control_src})

target_link_libraries(nm_access_control np_platform)
