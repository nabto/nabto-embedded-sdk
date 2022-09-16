#ifndef NM_MBEDTLS_UTIL_H
#define NM_MBEDTLS_UTIL_H

#include <platform/np_platform.h>
#include <platform/np_error_code.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>

#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(m) m
#endif

typedef struct nm_dtls_util_connection_ctx nm_dtls_util_connection_ctx;

np_error_code nm_mbedtls_util_fp_from_crt(const mbedtls_x509_crt* crt, uint8_t* fp);

np_error_code nm_mbedtls_create_crt_from_private_key(const char* privateKey, char** crt);

/**
 * take a 32 byte fingerprint buffer as input.
 */
np_error_code nm_mbedtls_get_fingerprint_from_private_key(const char* privateKey, uint8_t* fingerprint);

np_error_code nm_mbedtls_util_create_private_key(char** privateKey);

void nm_mbedtls_util_check_logging(mbedtls_ssl_config* conf);

int nm_mbedtls_sha256( const unsigned char *input, size_t ilen, unsigned char output[32] );

#endif //NM_MBEDTLS_UTIL_H
