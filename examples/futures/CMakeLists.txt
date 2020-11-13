set(src
  src/futures_example.c
  )

add_executable(futures_example_device "${src}")
install(TARGETS futures_example_device
  RUNTIME DESTINATION bin
  )
target_link_libraries(futures_example_device nabto_device)
