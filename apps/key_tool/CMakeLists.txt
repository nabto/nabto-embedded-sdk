set(csrc
  ${dtls_common_src}
  src/key_tool_main.c
  )

add_executable(key_tool "${csrc}")
target_link_libraries(key_tool 3rdparty_gopt 3rdparty_mbedtls apps_common)

install(TARGETS key_tool
  RUNTIME DESTINATION bin
  )
