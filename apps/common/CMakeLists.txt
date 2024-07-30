find_package(MbedTLS COMPONENTS mbedtls mbedcrypto mbedx509)
set(src
  json_config.c
  device_config.c
  private_key.c
  string_file.c
  random_string.c
  logging.c
  prompt_stdin.c
  )

add_library(apps_common ${src})
target_link_libraries(apps_common nabto_device 3rdparty_cjson nn MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
