set(src
  simple_speed_test.c
  )

add_executable(simple_speed_test "${src}")
target_link_libraries(simple_speed_test nabto_device)

install(TARGETS simple_speed_test
  RUNTIME DESTINATION bin
  )
