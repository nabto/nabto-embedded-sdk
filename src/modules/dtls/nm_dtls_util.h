#ifndef NM_DTLS_UTIL_H
#define NM_DTLS_UTIL_H

#include <platform/np_platform.h>
#include <platform/np_error_code.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>


enum sslState {
    CONNECTING,
    DATA,
    CLOSING
};

typedef struct nm_dtls_util_connection_ctx nm_dtls_util_connection_ctx;

np_error_code nm_dtls_util_fp_from_crt(const mbedtls_x509_crt* crt, uint8_t* fp);

np_error_code nm_dtls_create_crt_from_private_key(const char* privateKey, char** crt);

np_error_code nm_dtls_get_fingerprint_from_private_key(const char* privateKey, char** fingerprint);

np_error_code nm_dtls_util_create_private_key(char** privateKey);

#endif //NM_DTLS_UTIL_H
