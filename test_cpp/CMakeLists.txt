
set(CMAKE_CXX_STANDARD 14)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/3rdparty/boost 3rdparty_boost)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/3rdparty/fmtlib 3rdparty_fmtlib)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/src/util common_util)

set(test_src
  unit_test.cpp
  epoll/epoll_tcp_test.cpp
  )

add_executable(embedded_unit_test "${test_src}")
target_link_libraries(embedded_unit_test test_platform nm_epoll 3rdparty_boost_test 3rdparty_boost_asio common_util)
