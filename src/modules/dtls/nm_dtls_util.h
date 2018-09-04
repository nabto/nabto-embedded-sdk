#ifndef NM_DTLS_UTIL_H
#define NM_DTLS_UTIL_H

#include <mbedtls/x509_crt.h>
#include <platform/np_error_code.h>

np_error_code nm_dtls_util_fp_from_crt(const mbedtls_x509_crt* crt, uint8_t* fp);


#endif //NM_DTLS_UTIL_H
