
set(CMAKE_CXX_STANDARD 14)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/3rdparty/boost 3rdparty_boost)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/3rdparty/fmtlib 3rdparty_fmtlib)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/src/util common_util)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/src/dtls common_dtls)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../nabto-common-cpp/src/coap_cpp common_coap_cpp)


set(test_src
  helper.cpp
  unit_test.cpp
  network/tcp_test.cpp
  network/udp_test.cpp
  platform/hex_test.cpp
  platform/vector_test.cpp
  platform/list_test.cpp
  platform/ip_address_test.cpp
  platform/string_map_test.cpp
  platform/logging_test.cpp
  platform/event_queue_test.cpp
  api/event_handler_test.cpp
  api/future_test.cpp
  api/device_api.cpp
  api/authorization_test.cpp
  api/new_free.cpp
  api/create_sct.cpp
  attach/attach_test.cpp
  test_platform.cpp
  test_platform_test.cpp
  policies/condition_test.cpp
  policies/condition_json_test.cpp
  policies/statement_json_test.cpp
  policies/policy_json_test.cpp
  policies/policy_deny_test.cpp
  dns/dns_test.cpp

  )

add_executable(embedded_unit_test "${test_src}")
target_link_libraries(embedded_unit_test
  nabto_device_api
  #test_platform
  3rdparty_boost_test
  3rdparty_boost_asio
  common_util
  nc_core
  dtls
  nm_logging_test
  nm_policies
  nm_iam
  )

if (NOT WIN32)
  target_link_libraries(embedded_unit_test
    nm_timestamp
    nm_select_unix
    nm_unix_dns
    )
endif()

target_link_libraries(embedded_unit_test nm_libevent 3rdparty_libevent)

target_include_directories(embedded_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

install(TARGETS embedded_unit_test
  RUNTIME DESTINATION bin
  )
