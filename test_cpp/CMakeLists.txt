
set(CMAKE_CXX_STANDARD 14)

set(test_src
  util/io_service.cpp
  helper.cpp
  unit_test.cpp
  network/tcp_test.cpp
  network/udp_test.cpp
  platform/hex_test.cpp
  platform/ip_address_test.cpp
  platform/logging_test.cpp
  platform/timestamp_test.cpp
#  platform/event_queue_test.cpp
#  api/event_handler_test.cpp
#  api/future_test.cpp
  api/device_api.cpp
  api/authorization_test.cpp
  api/new_free.cpp
  api/create_sct.cpp
  # TODO move the attach_test to somewhere else where the dtls server
  #exists or move the dtls server to this repository
  #attach/attach_test.cpp
  test_platform.cpp
  test_platform_test.cpp
  policies/condition_test.cpp
  policies/condition_json_test.cpp
  policies/statement_json_test.cpp
  policies/policy_json_test.cpp
  policies/policy_deny_test.cpp
  dns/dns_test.cpp
  test_platform_event_queue.c

  )

add_subdirectory(../nabto-common/3rdparty/boost boost)

add_executable(embedded_unit_test "${test_src}")
target_link_libraries(embedded_unit_test

  #test_platform
  3rdparty_boost_test
  3rdparty_boost_asio
  #common_util
  nc_core
  #dtls
  nm_logging_test
  nm_policies
  nm_iam
  nabto_device_static
  3rdparty_boost_test
  )

if (HAVE_SELECT_UNIX)
  target_link_libraries(embedded_unit_test
    nm_select_unix
    nm_unix_dns
    nm_unix_timestamp
    )
endif()

target_link_libraries(embedded_unit_test nm_libevent 3rdparty_libevent)

target_include_directories(embedded_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

install(TARGETS embedded_unit_test
  RUNTIME DESTINATION bin
  )
