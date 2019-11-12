
set(CMAKE_CXX_STANDARD 14)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/3rdparty/boost 3rdparty_boost)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/3rdparty/fmtlib 3rdparty_fmtlib)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/src/util common_util)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/src/dtls common_dtls)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/src/coap_cpp common_coap_cpp)

INCLUDE(CheckIncludeFiles)
CHECK_INCLUDE_FILES("sys/epoll.h" HAVE_EPOLL_HEADERS)

if (HAVE_EPOLL_HEADERS)
  add_definitions(-DHAVE_EPOLL)
endif()

set(test_src
  unit_test.cpp
  network/tcp_test.cpp
  network/udp_test.cpp
  platform/hex_test.cpp
  api/event_handler_test.cpp
  api/future_test.cpp
  api/device_api.cpp
  attach/attach_test.cpp
  test_platform.cpp
  )

add_executable(embedded_unit_test "${test_src}")
target_link_libraries(embedded_unit_test
  nabto_device_api
  test_platform
  3rdparty_boost_test
  3rdparty_boost_asio
  common_util
  nm_select_unix
  nc_core
  dtls
)

if (HAVE_EPOLL_HEADERS)
  target_link_libraries(embedded_unit_test nm_epoll)
endif()

target_include_directories(embedded_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

install(TARGETS embedded_unit_test
  RUNTIME DESTINATION bin
  )
