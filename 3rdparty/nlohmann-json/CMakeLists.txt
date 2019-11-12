
add_library(3rdparty_json INTERFACE)
target_include_directories(3rdparty_json INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(3rdparty_json INTERFACE -Wno-psabi)
