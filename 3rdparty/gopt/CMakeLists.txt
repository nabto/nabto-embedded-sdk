set(src
  gopt/gopt.c
  )


add_library(3rdparty_gopt ${src})
target_include_directories(3rdparty_gopt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
