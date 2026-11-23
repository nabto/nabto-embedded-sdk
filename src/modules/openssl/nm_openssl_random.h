#ifndef NM_OPENSSL_RANDOM_H_
#define NM_OPENSSL_RANDOM_H_

#include <platform/np_platform.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool nm_openssl_random_init(struct np_platform* pl);

void nm_openssl_random_deinit(struct np_platform* pl);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
