#ifndef NM_MBEDTLS_UTIL_H
#define NM_MBEDTLS_UTIL_H

#include <platform/np_error_code.h>
#include <platform/np_platform.h>

#if !defined(DEVICE_MBEDTLS_2)
#include <mbedtls/build_info.h>
#endif
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

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

/**
 * Receive available udp application data from the ssl context. If the return
 * value > 0 the data is returned and must be freed after use by the caller. The
 * return value is otherwise identical to mbedtls_ssl_read. If a large enough
 * buffer cannot be allocated for the data the data is discarded.
 */
int nm_mbedtls_recv_data(mbedtls_ssl_context *ssl, uint8_t** data);

#endif // HOME_TFK_SANDBOX_NABTO_EMBEDDED_SDK_SRC_MODULES_MBEDTLS_NM_MBEDTLS_UTIL_H
