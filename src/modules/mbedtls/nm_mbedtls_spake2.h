#ifndef NM_MBEDTLS_SPAKE2_H_
#define NM_MBEDTLS_SPAKE2_H_

#include <platform/np_platform.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

np_error_code nm_mbedtls_spake2_init(struct np_platform* pl);

void nm_mbedtls_spake2_deinit(struct np_platform* pl);

np_error_code nm_mbedtls_spake2_calculate_key(
    struct nc_spake2_password_request* req,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng,
    const char* password,
    uint8_t* resp,
    size_t* respLen,
    uint8_t* spake2Key);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
