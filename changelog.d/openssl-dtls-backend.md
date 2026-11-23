### Added
 * OpenSSL can be used as the DTLS, password authentication (SPAKE2) and
   random module instead of mbedtls. Build with `-DNABTO_DEVICE_OPENSSL=ON`, or
   define `NABTO_DEVICE_OPENSSL` when not building with CMake. OpenSSL 3.5 or
   newer is required. The `linux_vcpkg_openssl` CMake preset builds it with
   OpenSSL from vcpkg (the `openssl` manifest feature).
 * * Device fingerprints, certificates and private keys are the same as with
     mbedtls, so a device keeps its identity when it changes module.
 * * The examples and tests still use mbedtls directly, so mbedtls is still
     needed to build them.
