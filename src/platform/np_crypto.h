#ifndef NP_CRYPTO_H
#define NP_CRYPTO_H

#include <core/nc_protocol_defines.h>

#include <platform/np_error_code.h>
#include <platform/np_connection.h>
#include <platform/np_platform.h>

typedef struct np_crypto_context np_crypto_context;

typedef void (*np_crypto_connect_callback)(const np_error_code ec, np_crypto_context* ctx, void* data);

typedef void (*np_crypto_send_to_callback)(const np_error_code ec, void* data);

typedef void (*np_crypto_received_callback)(const np_error_code ec, np_communication_buffer* buffer, uint16_t bufferSize, void* data);

typedef void (*np_crypto_close_callback)(const np_error_code ec, void* data);

struct np_crypto_module {

    np_error_code (*async_connect)(struct np_platform* pl, np_connection* conn, np_crypto_connect_callback cb, void* data);
    np_error_code (*async_send_to)(struct np_platform* pl, np_crypto_context* ctx, uint8_t* buffer, uint16_t bufferSize, np_crypto_send_to_callback cb, void* data);
    np_error_code (*async_recv_from)(struct np_platform* pl, np_crypto_context* ctx, enum application_data_type type, np_crypto_received_callback cb, void* data);
    np_error_code (*async_close)(struct np_platform* pl, np_crypto_context* ctx, np_crypto_close_callback cb, void* data);
};

#endif // NP_CRYPTO_H
