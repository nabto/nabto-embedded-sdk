#ifndef NP_DTLS_CLI_H
#define NP_DTLS_CLI_H

#include <core/nc_protocol_defines.h>

#include <platform/np_error_code.h>
#include <platform/np_dtls.h>
#include <platform/np_udp.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct nc_udp_dispatch_context;

enum np_dtls_cli_event {
    NP_DTLS_CLI_EVENT_CLOSED,
    NP_DTLS_CLI_EVENT_HANDSHAKE_COMPLETE
};

typedef void (*np_dtls_cli_send_callback)(const np_error_code ec, void* data);

typedef void (*np_dtls_cli_sender)(bool activeChannel,
                                   uint8_t* buffer, uint16_t bufferSize,
                                   np_dtls_cli_send_callback cb, void* data,
                                   void* senderData);
typedef void (*np_dtls_cli_event_handler)(enum np_dtls_cli_event event, void* data);
typedef void (*np_dtls_cli_data_handler)(uint8_t channelId, uint64_t sequence,
                                         uint8_t* buffer, uint16_t bufferSize, void* data);

typedef struct np_dtls_cli_context np_dtls_cli_context;

typedef void (*np_dtls_cli_connect_callback)(const np_error_code ec, np_dtls_cli_context* ctx, void* data);

struct np_dtls_cli_send_context {
    uint8_t* buffer;
    uint16_t bufferSize;
    np_dtls_send_to_callback cb;
    void* data;
    struct np_dtls_cli_send_context* next;
    struct np_dtls_cli_send_context* prev;
};

struct np_dtls_cli_module {

    np_error_code (*create)(struct np_platform* pl, np_dtls_cli_context** client,
                            np_dtls_cli_sender packetSender, np_dtls_cli_data_handler dataHandler,
                            np_dtls_cli_event_handler eventHandler, void* data);
    void (*destroy)(np_dtls_cli_context* client);

    np_error_code (*set_sni)(np_dtls_cli_context* ctx, const char* sni);

    np_error_code (*set_keys)(np_dtls_cli_context* ctx,
                              const unsigned char* publicKeyL, size_t publicKeySize,
                              const unsigned char* privateKeyL, size_t privateKeySize);
    np_error_code (*reset)(np_dtls_cli_context* ctx);
    np_error_code (*connect)(np_dtls_cli_context* ctx);
    np_error_code (*async_send_data)(np_dtls_cli_context* ctx,
                                     struct np_dtls_cli_send_context* sendCtx);
    np_error_code (*handle_packet)(struct np_dtls_cli_context* ctx,
                                   uint8_t* buffer, uint16_t bufferSize);

    np_error_code (*close)(np_dtls_cli_context* ctx);
    np_error_code (*get_fingerprint)(struct np_platform* pl, np_dtls_cli_context* ctx, uint8_t* fp);

    // The retransmission in the dtls handshake uses exponential backoff,
    // If minTimeout is 1000ms and maxTimeout is 5000ms the dtls implementation will
    // retry at something like 1s, 2s, 4s,
    np_error_code (*set_handshake_timeout)(np_dtls_cli_context* ctx, uint32_t minTimeout, uint32_t maxTimeout);

    const char* (*get_alpn_protocol)(np_dtls_cli_context* ctx);

    np_error_code (*get_packet_count)(np_dtls_cli_context* ctx, uint32_t* recvCount, uint32_t* sentCount);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NP_DTLS_CLI_H
