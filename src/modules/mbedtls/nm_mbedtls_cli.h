#ifndef NM_MBEDTLS_CLI_H
#define NM_MBEDTLS_CLI_H

#include <platform/np_dtls_cli.h>
#include <platform/np_platform.h>

#ifdef __cplusplus
extern "C" {
#endif

np_error_code nm_mbedtls_cli_init(struct np_platform* pl);
void nm_mbedtls_cli_deinit(struct np_platform* pl);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NM_MBEDTLS_CLI_H
