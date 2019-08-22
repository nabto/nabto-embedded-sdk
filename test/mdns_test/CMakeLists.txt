set(src
  mdns_test.c
  )

add_executable(mdns_test ${src})

target_link_libraries(mdns_test nm_mdns np_platform nm_timestamp test_platform nc_core)
