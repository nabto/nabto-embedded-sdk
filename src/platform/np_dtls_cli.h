#ifndef NP_DTLS_CLI_H
#define NP_DTLS_CLI_H

#include <core/nc_protocol_defines.h>

#include <platform/np_error_code.h>
#include <platform/np_dtls.h>

#include <nn/llist.h>

/**
 * DTLS Client interface
 *
 * Warning: this interface is not final.
 */



#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct nc_udp_dispatch_context;

enum np_dtls_cli_event {
    NP_DTLS_CLI_EVENT_CLOSED, // The connection is closed
    NP_DTLS_CLI_EVENT_HANDSHAKE_COMPLETE,
    NP_DTLS_CLI_EVENT_ACCESS_DENIED, // The connection got an access denied alert. The connection is closed.
    NP_DTLS_CLI_EVENT_CERTIFICATE_VERIFICATION_FAILED // The certificate could not be validated. The connection is closed.
};

typedef void (*np_dtls_cli_send_callback)(const np_error_code ec, void* data);

typedef np_error_code (*np_dtls_cli_sender)(uint8_t* buffer, uint16_t bufferSize,
                                            np_dtls_cli_send_callback cb, void* data,
                                            void* senderData);
typedef void (*np_dtls_cli_event_handler)(enum np_dtls_cli_event event, void* data);
typedef void (*np_dtls_cli_data_handler)(uint8_t* buffer, uint16_t bufferSize, void* data);

struct np_dtls_cli_context;

struct np_dtls_cli_send_context {
    uint8_t* buffer;
    uint16_t bufferSize;
    np_dtls_send_to_callback cb;
    void* data;
    struct nn_llist_node sendListNode;
};

struct np_dtls_cli_module {

    np_error_code (*create)(struct np_platform* pl, struct np_dtls_cli_context** client,
                            np_dtls_cli_sender packetSender, np_dtls_cli_data_handler dataHandler,
                            np_dtls_cli_event_handler eventHandler, void* data);
    void (*destroy)(struct np_dtls_cli_context* client);

    np_error_code (*set_sni)(struct np_dtls_cli_context* ctx, const char* sni);

    // The certificate is a pem encoded certificate matching the pem encoded private key.
    np_error_code (*set_keys)(struct np_dtls_cli_context* ctx,
                              const unsigned char* certificate, size_t certificateSize,
                              const unsigned char* privateKeyL, size_t privateKeySize);

    np_error_code (*set_root_certs)(struct np_dtls_cli_context* ctx, const char* rootCerts);
    np_error_code (*disable_certificate_validation)(struct np_dtls_cli_context* ctx);
    np_error_code (*reset)(struct np_dtls_cli_context* ctx);
    np_error_code (*connect)(struct np_dtls_cli_context* ctx);
    np_error_code (*async_send_data)(struct np_dtls_cli_context* ctx,
                                     struct np_dtls_cli_send_context* sendCtx);
    np_error_code (*handle_packet)(struct np_dtls_cli_context* ctx,
                                   uint8_t* buffer, uint16_t bufferSize);

    np_error_code (*close)(struct np_dtls_cli_context* ctx);
    np_error_code (*get_fingerprint)(struct np_dtls_cli_context* ctx, uint8_t* fp);

    // The retransmission in the dtls handshake uses exponential backoff,
    // If minTimeout is 1000ms and maxTimeout is 5000ms the dtls implementation will
    // retry at something like 1s, 2s, 4s,
    np_error_code (*set_handshake_timeout)(struct np_dtls_cli_context* ctx, uint32_t minTimeout, uint32_t maxTimeout);

    const char* (*get_alpn_protocol)(struct np_dtls_cli_context* ctx);

    np_error_code (*get_packet_count)(struct np_dtls_cli_context* ctx, uint32_t* recvCount, uint32_t* sentCount);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NP_DTLS_CLI_H
