find_path(MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h)

find_library(MBEDTLS_LIBRARY mbedtls)
find_library(MBEDX509_LIBRARY mbedx509)
find_library(MBEDCRYPTO_LIBRARY mbedcrypto)

set(MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARY}" "${MBEDX509_LIBRARY}" "${MBEDCRYPTO_LIBRARY}")

if(MBEDTLS_LIBRARY AND NOT TARGET MbedTLS::mbedtls)
  add_library(MbedTLS::mbedtls STATIC IMPORTED)
  target_link_libraries(MbedTLS::mbedtls INTERFACE "${MBEDTLS_LIBRARY}")
  set_target_properties(MbedTLS::mbedtls PROPERTIES IMPORTED_LOCATION "${MBEDTLS_LIBRARY}")
  target_include_directories(MbedTLS::mbedtls INTERFACE "${MBEDTLS_INCLUDE_DIRS}")

  add_library(MbedTLS::mbedcrypto STATIC IMPORTED)
  target_link_libraries(MbedTLS::mbedcrypto INTERFACE "${MBEDCRYPTO_LIBRARY}")
  set_target_properties(MbedTLS::mbedcrypto PROPERTIES IMPORTED_LOCATION "${MBEDCRYPTO_LIBRARY}")
  target_include_directories(MbedTLS::mbedcrypto INTERFACE "${MBEDTLS_INCLUDE_DIRS}")

  add_library(MbedTLS::mbedx509 STATIC IMPORTED)
  target_link_libraries(MbedTLS::mbedx509 INTERFACE "${MBEDX509_LIBRARY}")
  set_target_properties(MbedTLS::mbedx509 PROPERTIES IMPORTED_LOCATION "${MBEDX509_LIBRARY}")
  target_include_directories(MbedTLS::mbedx509 INTERFACE ${MBEDTLS_INCLUDE_DIRS})

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(MbedTLS DEFAULT_MSG
    MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)

  mark_as_advanced(MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)
endif()
