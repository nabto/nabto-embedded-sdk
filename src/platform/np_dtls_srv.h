#ifndef NP_DTLS_SRV_H
#define NP_DTLS_SRV_H

#include <platform/np_error_code.h>
#include <platform/np_dtls.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NP_DTLS_SRV_DEFAULT_CHANNEL_ID 0xff

enum np_dtls_srv_event {
    NP_DTLS_SRV_EVENT_CLOSED,
    NP_DTLS_SRV_EVENT_HANDSHAKE_COMPLETE
};

typedef void (*np_dtls_srv_send_callback)(const np_error_code ec, void* data);
typedef void (*np_dtls_srv_sender)(uint8_t channelId,
                                   np_communication_buffer* buffer, uint16_t bufferSize,
                                   np_dtls_srv_send_callback cb, void* data,
                                   void* senderData);
typedef void (*np_dtls_srv_event_handler)(enum np_dtls_srv_event event, void* data);
typedef void (*np_dtls_srv_data_handler)(uint8_t channelId, uint64_t sequence,
                                         np_communication_buffer* buffer, uint16_t bufferSize, void* data);

struct np_dtls_srv_send_context {
    uint8_t* buffer;
    uint16_t bufferSize;
    uint8_t channelId;
    np_dtls_send_to_callback cb;
    void* data;
    struct np_dtls_srv_send_context* next;
    struct np_dtls_srv_send_context* prev;
};

#include <core/nc_protocol_defines.h>

struct np_platform;

typedef struct np_dtls_srv_connection np_dtls_srv_connection;

struct np_dtls_srv;

struct np_dtls_srv_module {

    np_error_code (*create)(struct np_platform* pl, struct np_dtls_srv** server);
    np_error_code (*set_keys)(struct np_dtls_srv* server,
                              const unsigned char* publicKeyL, size_t publicKeySize,
                              const unsigned char* privateKeyL, size_t privateKeySize);
    void (*destroy)(struct np_dtls_srv* server);

    np_error_code (*create_connection)(struct np_dtls_srv* server, struct np_dtls_srv_connection** dtls,
                                       np_dtls_srv_sender packetSender, np_dtls_srv_data_handler dataHandler,
                                       np_dtls_srv_event_handler eventHandler, void* data);
    void (*destroy_connection)(struct np_dtls_srv_connection* connection);

    np_error_code (*async_send_data)(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                     struct np_dtls_srv_send_context* sendCtx);

    np_error_code (*handle_packet)(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                   uint8_t channelId, np_communication_buffer* buffer, uint16_t bufferSize);

    np_error_code (*async_close)(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                 np_dtls_close_callback cb, void* data);

    np_error_code (*get_fingerprint)(struct np_platform* pl, struct np_dtls_srv_connection* ctx, uint8_t* fp);

    const char* (*get_alpn_protocol)(struct np_dtls_srv_connection* ctx);

    np_error_code (*get_packet_count)(struct np_dtls_srv_connection* ctx, uint32_t* recvCount, uint32_t* sentCount);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NP_DTLS_SRV_H
