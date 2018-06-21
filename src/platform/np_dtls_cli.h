#ifndef NP_DTLS_CLI_H
#define NP_DTLS_CLI_H

#include <core/nc_protocol_defines.h>

#include <platform/np_error_code.h>
#include <platform/np_connection.h>
#include <platform/np_platform.h>

typedef struct np_dtls_cli_context np_dtls_cli_context;

typedef void (*np_dtls_cli_connect_callback)(const np_error_code ec, np_dtls_cli_context* ctx, void* data);

typedef void (*np_dtls_cli_send_to_callback)(const np_error_code ec, void* data);

typedef void (*np_dtls_cli_received_callback)(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                                            np_communication_buffer* buffer, uint16_t bufferSize, void* data);

typedef void (*np_dtls_cli_close_callback)(const np_error_code ec, void* data);

struct np_dtls_cli_module {

    np_error_code (*async_connect)(struct np_platform* pl, np_connection* conn,
                                   np_dtls_cli_connect_callback cb, void* data);
    np_error_code (*async_send_to)(struct np_platform* pl, np_dtls_cli_context* ctx, uint8_t channelId,
                                   uint8_t* buffer, uint16_t bufferSize, np_dtls_cli_send_to_callback cb, void* data);
    np_error_code (*async_recv_from)(struct np_platform* pl, np_dtls_cli_context* ctx,
                                     enum application_data_type type, np_dtls_cli_received_callback cb, void* data);
    np_error_code (*cancel_recv_from)(struct np_platform* pl, np_dtls_cli_context* ctx,
                                      enum application_data_type type);
    np_error_code (*async_close)(struct np_platform* pl, np_dtls_cli_context* ctx,
                                 np_dtls_cli_close_callback cb, void* data);
};

#endif // NP_DTLS_CLI_H
