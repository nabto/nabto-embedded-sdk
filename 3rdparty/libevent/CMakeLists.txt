
set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable libevent openssl")
set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "disable libevent benchmarks")
set(EVENT__DISABLE_TESTS ON CACHE BOOL "disable libevent tests")
set(EVENT__DISABLE_REGRESS ON CACHE BOOL "disable libevent regression tests")
set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "disable libevent samples")
set(EVENT__LIBRARY_TYPE STATIC CACHE STRING "libevent library type")

include_directories(libevent/include)
add_subdirectory(libevent)

add_library(3rdparty_libevent INTERFACE)
target_link_libraries(3rdparty_libevent INTERFACE event_core event_extra event_pthreads)

target_include_directories(3rdparty_libevent INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/libevent/include)
target_include_directories(3rdparty_libevent INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/libevent/include)
