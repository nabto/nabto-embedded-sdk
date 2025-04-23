#ifndef NM_WOLFSSL_SPAKE2_H_
#define NM_WOLFSSL_SPAKE2_H_

#include <platform/np_platform.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

np_error_code nm_wolfssl_spake2_init(struct np_platform* pl);

void nm_wolfssl_spake2_deinit(struct np_platform* pl);

bool nm_wolfssl_spake2_test();

#ifdef __cplusplus
} //extern "C"
#endif

#endif
