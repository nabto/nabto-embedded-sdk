#ifndef _NM_MBEDTLS_RANDOM_H_
#define _NM_MBEDTLS_RANDOM_H_

#include <stdbool.h>
#include <platform/np_platform.h>

bool nm_mbedtls_random_init(struct np_platform* pl);

void nm_mbedtls_random_deinit(struct np_platform* pl);

#endif
