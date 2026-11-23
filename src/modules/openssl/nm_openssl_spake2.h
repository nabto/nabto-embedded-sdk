#ifndef NM_OPENSSL_SPAKE2_H_
#define NM_OPENSSL_SPAKE2_H_

#include <platform/np_platform.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

np_error_code nm_openssl_spake2_init(struct np_platform* pl);

void nm_openssl_spake2_deinit(struct np_platform* pl);

/**
 * Calculate the spake2 key with the random value y given by the caller instead
 * of a random one, such that the result is deterministic in tests. If y is NULL
 * a random value is used.
 */
np_error_code nm_openssl_spake2_calculate_key_with_y(
    struct nc_spake2_password_request* req, const uint8_t* y, size_t yLen,
    const char* password, uint8_t* resp, size_t* respLen, uint8_t* spake2Key);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
