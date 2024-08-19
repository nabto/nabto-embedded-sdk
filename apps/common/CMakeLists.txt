find_package(MbedTLS COMPONENTS mbedtls mbedcrypto mbedx509)
find_package(cJSON REQUIRED)
find_package(NabtoCommon REQUIRED)
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
target_link_libraries(apps_common nabto_device cjson NabtoCommon::nn MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
