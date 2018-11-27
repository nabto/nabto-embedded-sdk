#ifndef NP_DTLS_CLI_H
#define NP_DTLS_CLI_H

#include <core/nc_protocol_defines.h>

#include <platform/np_error_code.h>
#include <platform/np_dtls.h>
#include <platform/np_udp.h>

struct np_platform;

typedef struct np_dtls_cli_context np_dtls_cli_context;

typedef void (*np_dtls_cli_connect_callback)(const np_error_code ec, np_dtls_cli_context* ctx, void* data);

struct np_dtls_cli_module {

    np_error_code (*async_connect)(struct np_platform* pl, np_udp_socket* conn, np_udp_endpoint ep,
                                   np_dtls_cli_connect_callback cb, void* data);
    np_error_code (*async_send_to)(struct np_platform* pl, np_dtls_cli_context* ctx, uint8_t channelId,
                                   uint8_t* buffer, uint16_t bufferSize, np_dtls_send_to_callback cb, void* data);
    np_error_code (*async_recv_from)(struct np_platform* pl, np_dtls_cli_context* ctx,
                                     enum application_data_type type, np_dtls_received_callback cb, void* data);
    np_error_code (*cancel_recv_from)(struct np_platform* pl, np_dtls_cli_context* ctx,
                                      enum application_data_type type);
    np_error_code (*async_close)(struct np_platform* pl, np_dtls_cli_context* ctx,
                                 np_dtls_close_callback cb, void* data);
    np_error_code (*get_fingerprint)(struct np_platform* pl, np_dtls_cli_context* ctx, uint8_t* fp);

    const char* (*get_alpn_protocol)(np_dtls_cli_context* ctx);

    np_error_code (*get_packet_count)(np_dtls_cli_context* ctx, uint32_t* recvCount, uint32_t* sentCount);

    np_error_code (*start_keep_alive)(np_dtls_cli_context* ctx, uint32_t interval,
                                      uint8_t retryInterval, uint8_t maxRetries);
};

#endif // NP_DTLS_CLI_H
