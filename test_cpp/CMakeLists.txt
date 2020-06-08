
set(CMAKE_CXX_STANDARD 14)

set(test_src
  util/io_service.cpp
  util/tcp_echo_server.cpp
  util/helper.cpp

  unit_test.cpp

  platform/test_platform.cpp
  platform/test_platform_test.cpp
  platform/test_platform_event_queue.c

  tests/network/tcp_test.cpp
  tests/network/udp_test.cpp
  tests/platform/hex_test.cpp
  tests/platform/ip_address_test.cpp
  tests/platform/logging_test.cpp
  tests/platform/timestamp_test.cpp
#  tests/platform/event_queue_test.cpp
#  tests/api/event_handler_test.cpp
#  tests/api/future_test.cpp
  tests/api/device_api.cpp
  tests/api/authorization_test.cpp
  tests/api/new_free.cpp
  tests/api/create_sct.cpp
  tests/api/private_key_test.cpp
  # TODO move the attach_test to somewhere else where the dtls server
  #exists or move the dtls server to this repository
  #tests/attach/attach_test.cpp
  tests/policies/condition_test.cpp
  tests/policies/condition_json_test.cpp
  tests/policies/statement_json_test.cpp
  tests/policies/policy_json_test.cpp
  tests/policies/policy_deny_test.cpp
  tests/dns/dns_test.cpp

  )

add_subdirectory(../nabto-common/3rdparty/boost boost)

add_executable(embedded_unit_test "${test_src}")
target_link_libraries(embedded_unit_test

  #test_platform
  3rdparty_boost_test
  3rdparty_boost_asio
  nm_communication_buffer
  #common_util
  nc_core
  #dtls
  nm_logging_test
  nm_policies
  nm_iam
  nabto_device_static
  3rdparty_boost_test
  np_platform
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
target_include_directories(embedded_unit_test PRIVATE platform)

install(TARGETS embedded_unit_test
  RUNTIME DESTINATION bin
  )
