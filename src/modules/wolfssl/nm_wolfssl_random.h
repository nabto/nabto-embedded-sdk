#ifndef NM_WOLFSSL_RANDOM_H_
#define NM_WOLFSSL_RANDOM_H_

#include <platform/np_platform.h>
#include <stdbool.h>

bool nm_wolfssl_random_init(struct np_platform* pl);

void nm_wolfssl_random_deinit(struct np_platform* pl);

#endif
