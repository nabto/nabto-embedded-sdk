set(src
  gopt/gopt.c
  )


add_library(3rdparty_gopt ${src})
if (WIN32)
  target_compile_options(3rdparty_gopt INTERFACE /w)
else()
  target_compile_options(3rdparty_gopt INTERFACE -w)
endif()
target_include_directories(3rdparty_gopt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
