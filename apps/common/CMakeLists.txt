set(src
  json_config.c
  device_config.c
  private_key.c
  string_file.c
  random_string.c
  logging.c
  )

add_library(apps_common ${src})
target_link_libraries(apps_common 3rdparty_cjson 3rdparty_mbedtls 3rdparty_nn)
