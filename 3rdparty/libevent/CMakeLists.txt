
set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable libevent openssl")
set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "disable libevent benchmarks")
set(EVENT__DISABLE_TESTS ON CACHE BOOL "disable libevent tests")
set(EVENT__DISABLE_REGRESS ON CACHE BOOL "disable libevent regression tests")
set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "disable libevent samples")
set(EVENT__LIBRARY_TYPE STATIC CACHE STRING "libevent library type")

include_directories(libevent/include)

add_subdirectory(libevent EXCLUDE_FROM_ALL)

add_library(3rdparty_libevent INTERFACE)

target_link_libraries(3rdparty_libevent INTERFACE event_core event_extra)

if (NOT WIN32)
  target_link_libraries(3rdparty_libevent INTERFACE event_pthreads)
endif()

target_include_directories(3rdparty_libevent INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/libevent/include)
target_include_directories(3rdparty_libevent INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/libevent/include)
