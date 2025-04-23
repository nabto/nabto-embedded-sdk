#ifndef NM_MBEDTLS_RANDOM_H_
#define NM_MBEDTLS_RANDOM_H_

#include <platform/np_platform.h>
#include <stdbool.h>

bool nm_mbedtls_random_init(struct np_platform* pl);

void nm_mbedtls_random_deinit(struct np_platform* pl);

#endif
