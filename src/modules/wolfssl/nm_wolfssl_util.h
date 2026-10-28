#ifndef NM_wolfssl_UTIL_H
#define NM_wolfssl_UTIL_H

#include <platform/np_error_code.h>
#include <platform/np_platform.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nm_dtls_util_connection_ctx nm_dtls_util_connection_ctx;

np_error_code nm_wolfssl_util_fp_from_crt(const WOLFSSL_X509* crt, uint8_t* fp);

np_error_code nm_wolfssl_create_crt_from_private_key(const char* privateKey, char** crt);

/**
 * take a 32 byte fingerprint buffer as input.
 */
np_error_code nm_wolfssl_get_fingerprint_from_private_key(const char* privateKey, uint8_t* fingerprint);

np_error_code nm_wolfssl_util_create_private_key(char** privateKey);

void nm_wolfssl_util_check_logging();

/**
 * Get the dtls mtu, which is the size of a communication buffer as each record
 * is written into one before it is sent. A buffer is allocated to read the
 * size, so call this when the module is set up and cache the result rather
 * than calling it per connection.
 */
np_error_code nm_wolfssl_util_get_mtu(struct np_platform* pl, uint16_t* mtu);

/**
 * Limit the size of the records the ssl object sends to mtu. Requires wolfSSL
 * built with WOLFSSL_DTLS_MTU, otherwise this does nothing and the send
 * callbacks drop records which do not fit.
 */
np_error_code nm_wolfssl_util_set_mtu(WOLFSSL* ssl, uint16_t mtu);

#ifdef __cplusplus
} // extern "C"
#endif

#endif //NM_wolfssl_UTIL_H
