#ifndef _NM_MBEDTLS_SPAKE2_H_
#define _NM_MBEDTLS_SPAKE2_H_

#include <stdbool.h>
#include <platform/np_platform.h>

np_error_code nm_mbedtls_spake2_init(struct np_platform* pl);

void nm_mbedtls_spake2_deinit(struct np_platform* pl);

#endif
