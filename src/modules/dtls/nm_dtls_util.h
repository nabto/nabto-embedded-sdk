#ifndef NM_DTLS_UTIL_H
#define NM_DTLS_UTIL_H

#include <platform/np_platform.h>
#include <platform/np_error_code.h>
#include <core/nc_keep_alive.h>
#include <core/nc_protocol_defines.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>


enum sslState {
    CONNECTING,
    DATA,
    CLOSING
};

struct nm_dtls_util_connection_ctx {
    enum sslState state;
    struct np_event closeEv;
    struct np_timed_event tEv;

    np_dtls_close_callback closeCb;
    void* closeCbData;

    uint32_t recvCount;
    uint32_t sentCount;
    uint8_t currentChannelId;
    mbedtls_ssl_context ssl;

    uint8_t* recvBuffer;
    size_t recvBufferSize;

    np_communication_buffer* sslRecvBuf;
//    size_t sslRecvBufSize;
    np_communication_buffer* sslSendBuffer;
    size_t sslSendBufferSize;

    np_timestamp intermediateTp;
    np_timestamp finalTp;

};


typedef struct nm_dtls_util_connection_ctx nm_dtls_util_connection_ctx;

np_error_code nm_dtls_util_fp_from_crt(const mbedtls_x509_crt* crt, uint8_t* fp);

np_error_code nm_dtls_create_crt_from_private_key(const char* privateKey, char** crt);

np_error_code nm_dtls_get_fingerprint_from_private_key(const char* privateKey, char** fingerprint);

np_error_code nm_dtls_util_create_private_key(char** privateKey);

#endif //NM_DTLS_UTIL_H
