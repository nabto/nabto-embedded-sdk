
set(src_dir ${CMAKE_CURRENT_SOURCE_DIR}/nn/src)

set(src
  ${src_dir}/nn/log.c
  ${src_dir}/nn/vector.c
  )

add_library(3rdparty_nn "${src}")

target_include_directories(3rdparty_nn PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/nn/include)
