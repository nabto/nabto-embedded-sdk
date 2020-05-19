#ifndef NM_DTLS_SRV_H
#define NM_DTLS_SRV_H

#include <platform/np_platform.h>
#include <platform/np_dtls_srv.h>

#ifdef __cplusplus
extern "C" {
#endif

np_error_code nm_dtls_srv_init(struct np_platform* pl);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NM_DTLS_SRV_H
