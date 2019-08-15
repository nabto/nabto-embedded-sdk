
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(test_platform)
add_subdirectory(api_test)
add_subdirectory(test_device)
add_subdirectory(mdns_test)
#add_subdirectory(dtls_tester)
add_subdirectory(dtls_server_tester)
#add_subdirectory(coap_udp_tester)
add_subdirectory(low_lvl_api_tester)
