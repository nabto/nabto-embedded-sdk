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


#define NABTO_SSL_RECV_BUFFER_SIZE 4096
#define NABTO_DTLS_MAX_RECV_CBS 5
#define SERVER_NAME "localhost"

enum sslState {
    CONNECTING,
    DATA,
    CLOSING
};

struct nm_dtls_util_recv_cb_ctx {
    np_dtls_received_callback cb;
    void* data;
};

struct nm_dtls_util_connection_ctx {
    enum sslState state;
    struct np_event sendEv;
    struct np_event recvEv;
    struct np_event closeEv;
    struct np_timed_event tEv;
    struct nc_keep_alive_context keepAliveCtx;

    np_dtls_close_callback closeCb;
    void* closeCbData;
    np_dtls_send_to_callback sendCb;
    void* sendCbData;
    struct nm_dtls_util_recv_cb_ctx recvCb;

    uint32_t recvCount;
    uint32_t sentCount;
    uint8_t sendChannel;
    uint8_t currentChannelId;
    mbedtls_ssl_context ssl;

    uint8_t recvBuffer[NABTO_SSL_RECV_BUFFER_SIZE];
    size_t recvBufferSize;
    uint8_t* sendBuffer;
    uint16_t sendBufferSize;

    np_communication_buffer* sslRecvBuf;
//    size_t sslRecvBufSize;
    np_communication_buffer* sslSendBuffer;
    size_t sslSendBufferSize;

    np_timestamp intermediateTp;
    np_timestamp finalTp;

};


typedef struct nm_dtls_util_connection_ctx nm_dtls_util_connection_ctx;

np_error_code nm_dtls_util_fp_from_crt(const mbedtls_x509_crt* crt, uint8_t* fp);


#endif //NM_DTLS_UTIL_H
