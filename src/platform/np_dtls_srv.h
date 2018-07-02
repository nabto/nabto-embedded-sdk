#ifndef NP_DTLS_SRV_H
#define NP_DTLS_SRV_H

#include <core/nc_protocol_defines.h>

#include <platform/np_error_code.h>
#include <platform/np_connection.h>

struct np_platform;

typedef struct np_dtls_srv_connection np_dtls_srv_connection;

typedef void (*np_dtls_srv_send_to_callback)(const np_error_code ec, void* data);

typedef void (*np_dtls_srv_received_callback)(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                                              np_communication_buffer* buffer, uint16_t bufferSize, void* data);

typedef void (*np_dtls_srv_close_callback)(const np_error_code ec, void* data);

struct np_dtls_srv_module {

    np_error_code (*create)(struct np_platform* pl, np_connection* conn, np_dtls_srv_connection** dtls);
    np_error_code (*async_send_to)(struct np_platform* pl, np_dtls_srv_connection* ctx, uint8_t channelId,
                                   uint8_t* buffer, uint16_t bufferSize,
                                   np_dtls_srv_send_to_callback cb, void* data);
    np_error_code (*async_recv_from)(struct np_platform* pl, np_dtls_srv_connection* ctx,
                                     np_dtls_srv_received_callback cb, void* data);
    np_error_code (*cancel_recv_from)(struct np_platform* pl, np_dtls_srv_connection* ctx,
                                      enum application_data_type type);
    np_error_code (*async_close)(struct np_platform* pl, np_dtls_srv_connection* ctx,
                                 np_dtls_srv_close_callback cb, void* data);
};

#endif // NP_DTLS_SRV_H
