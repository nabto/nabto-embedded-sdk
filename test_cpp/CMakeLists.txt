find_package(Boost COMPONENTS asio unit_test_framework)
set(CMAKE_CXX_STANDARD 14)

set(util_src
  util/io_service.cpp
  util/tcp_echo_server.cpp
  util/helper.cpp

)

set(test_src
  unit_test.cpp

  platform/test_platform.cpp
  platform/test_platform_test.cpp

  fixtures/coap_server/coap_server_test.cpp
  tests/network/tcp_test.cpp
  tests/network/udp_test.cpp
  tests/platform/hex_test.cpp
  tests/platform/ip_address_test.cpp
  tests/platform/logging_test.cpp
  tests/platform/timestamp_test.cpp
#  tests/platform/event_queue_test.cpp
#  tests/api/event_handler_test.cpp
  tests/api/error_codes_test.cpp
  tests/api/device_api.cpp
  tests/api/virtual_connection_test.cpp
  tests/api/virtual_stream_test.cpp
  tests/api/authorization_test.cpp
  tests/api/new_free.cpp
  tests/api/create_sct.cpp
  tests/api/private_key_test.cpp
  tests/api/password_authorization_request_test.cpp
  tests/api/fcm_test.cpp
  tests/api/ice_servers_test.cpp
  tests/api/service_invoke_test.cpp
  tests/api/shutdown.cpp
  tests/api/get_attach_certificate_expiration.cpp
  tests/attach/attach_test.cpp
  tests/attach/basestation_fixture_test.cpp
  tests/iam/iam.cpp
  tests/iam/iam_util.cpp
  tests/iam/state.cpp
  tests/iam/serializer.cpp
  tests/policies/condition_test.cpp
  tests/policies/condition_json_test.cpp
  tests/policies/statement_test.cpp
  tests/policies/statement_json_test.cpp
  tests/policies/policy_test.cpp
  tests/policies/policy_json_test.cpp
  tests/dns/dns_test.cpp
  tests/local_ping/local_ping_test.cpp
  tests/core/nc_coap_rest_error_test.cpp
  tests/spake2/spake2_test.cpp
  tests/spake2/spake2_wolfssl_test.cpp
  ../src/api_test/nabto_device_test_logging.c
  )

add_subdirectory(fixtures/udp_server)
add_subdirectory(fixtures/coap_server)
add_subdirectory(fixtures/dtls_server)

add_library(test_util ${util_src})
target_include_directories(test_util PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_util Boost::asio NabtoCommon::nn nabto_device)


add_executable(embedded_unit_test "${test_src}")
target_link_libraries(embedded_unit_test

  #test_platform
  Boost::unit_test_framework
  Boost::asio
  nm_communication_buffer
  #common_util
  nc_core
  dtls_server_cpp
  nm_logging_test
  nm_iam
  nabto_device
  np_platform
  nm_event_queue
  test_util
  )

if (HAVE_SELECT_UNIX)
  target_link_libraries(embedded_unit_test
    nm_select_unix
    nm_unix_dns
    nm_unix_timestamp
    )
endif()

target_link_libraries(embedded_unit_test nm_libevent 3rdparty_json)

target_include_directories(embedded_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(embedded_unit_test PRIVATE platform)

install(TARGETS embedded_unit_test
  RUNTIME DESTINATION bin
  )
