#include "nm_dtls_util.h"
#include <mbedtls/sha256.h>

#include <string.h>

np_error_code nm_dtls_util_fp_from_crt(const mbedtls_x509_crt* crt, uint8_t* fp)
{
    uint8_t buffer[256];
    uint8_t fullSha[32];
    
    mbedtls_pk_context *ctx = (mbedtls_pk_context*)(&crt->pk);
    int len = mbedtls_pk_write_pubkey_der( ctx, buffer, sizeof(buffer));
    if (len <= 0) {
        return NABTO_EC_FAILED;
    }
    mbedtls_sha256_ret(buffer+sizeof(buffer)-len, len, fullSha, 0);
    memcpy(fp, fullSha, 16);
    return NABTO_EC_OK;
}
