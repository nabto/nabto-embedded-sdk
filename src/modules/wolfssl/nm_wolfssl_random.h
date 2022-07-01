#ifndef _NM_WOLFSSL_RANDOM_H_
#define _NM_WOLFSSL_RANDOM_H_

#include <stdbool.h>
#include <platform/np_platform.h>

bool nm_wolfssl_random_init(struct np_platform* pl);

void nm_wolfssl_random_deinit(struct np_platform* pl);

#endif
