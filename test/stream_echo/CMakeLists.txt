cmake_minimum_required(VERSION 3.0)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(stream_echo_src
  ${src_dir}/main.c
  )

add_executable(stream_echo "${stream_echo_src}")

target_link_libraries(stream_echo
  nabto_device
  )
