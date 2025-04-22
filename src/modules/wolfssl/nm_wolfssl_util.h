#ifndef NM_wolfssl_UTIL_H
#define NM_wolfssl_UTIL_H

#include <platform/np_error_code.h>
#include <platform/np_platform.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/ssl.h>

typedef struct nm_dtls_util_connection_ctx nm_dtls_util_connection_ctx;

np_error_code nm_wolfssl_util_fp_from_crt(const WOLFSSL_X509* crt, uint8_t* fp);

np_error_code nm_wolfssl_create_crt_from_private_key(const char* privateKey, char** crt);

/**
 * take a 32 byte fingerprint buffer as input.
 */
np_error_code nm_wolfssl_get_fingerprint_from_private_key(const char* privateKey, uint8_t* fingerprint);

np_error_code nm_wolfssl_util_create_private_key(char** privateKey);

void nm_wolfssl_util_check_logging();

#endif //NM_wolfssl_UTIL_H
