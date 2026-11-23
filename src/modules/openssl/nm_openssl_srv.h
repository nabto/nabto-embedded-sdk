#ifndef NM_OPENSSL_SRV_H
#define NM_OPENSSL_SRV_H

#include <platform/np_dtls_srv.h>
#include <platform/np_platform.h>

#ifdef __cplusplus
extern "C" {
#endif

np_error_code nm_openssl_srv_init(struct np_platform* pl);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NM_OPENSSL_SRV_H
