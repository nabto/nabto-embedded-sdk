set(src
  cjson/cJSON.c
  )

add_library(3rdparty_cjson ${src})
target_include_directories(3rdparty_cjson PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
