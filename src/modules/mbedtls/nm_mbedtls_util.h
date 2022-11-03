#ifndef NM_MBEDTLS_UTIL_H
#define NM_MBEDTLS_UTIL_H

//#include <platform/np_platform.h>
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

/**
 * Take a 32 byte raw private key and convert it to the PEM format used for nabto_device_set_private_key(),
 *
 * @param key    32 byte input key
 * @param keyLen 32
 * @param pemKey resulting private key. must be freed when done.
 * @return np_error_code ok on success
 */
np_error_code nm_mbedtls_util_pem_from_secp256r1(const uint8_t* key,
                                                 size_t keyLen, char** pemKey);

/**
 * Take a PEM encoded key and convert it to a 32 byte raw key.
 *
 * @param key    PEM encoded key
 * @param keyLen length of key
 * @param rawKey Resulting raw key
 * @param rawKeyLen length of rawKey buffer. Must be at least 32.
 * @return np_error_code OK on success
 */
np_error_code nm_mbedtls_util_secp256r1_from_pem(const char* key, size_t keyLen,
                                                 uint8_t* rawKey, size_t rawKeyLen);

/**
 * Receive available udp application data from the ssl context. If the return
 * value > 0 the data is returned and must be freed after use by the caller. The
 * return value is otherwise identical to mbedtls_ssl_read. If a large enough
 * buffer cannot be allocated for the data the data is discarded.
 */
int nm_mbedtls_recv_data(mbedtls_ssl_context *ssl, uint8_t** data);

#endif //NM_MBEDTLS_UTIL_H
