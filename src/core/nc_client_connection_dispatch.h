#ifndef NC_CLIENT_CONNECTION_DISPATCH_H
#define NC_CLIENT_CONNECTION_DISPATCH_H

#include <core/nc_client_connection.h>
#include <core/nc_connection.h>

#include <nn/llist.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nc_udp_dispatch_context;

typedef void (*nc_client_connection_dispatch_close_callback)(void* data);

struct nc_client_connection_dispatch_context {
    struct np_platform* pl;
    struct nc_device_context* device;
    struct nc_connections_context* connections;
    nc_client_connection_dispatch_close_callback closeCb;
    void* closeData;
    bool closing;
    bool sendingInternalError;
    struct np_completion_event sendCompletionEvent;
};

np_error_code nc_client_connection_dispatch_init(struct nc_client_connection_dispatch_context* ctx,
                                        struct np_platform* pl,
                                        struct nc_device_context* device);

void nc_client_connection_dispatch_deinit(struct nc_client_connection_dispatch_context* ctx);

/**
 * Returns NABTO_EC_OK if closing
 *         NABTO_EC_STOPPED if no connections needed to be closed
 */
np_error_code nc_client_connection_dispatch_async_close(struct nc_client_connection_dispatch_context* ctx, nc_client_connection_dispatch_close_callback cb, void* data);

void nc_client_connection_dispatch_handle_packet(struct nc_client_connection_dispatch_context* ctx,
                                              struct nc_udp_dispatch_context* udp, struct np_udp_endpoint* ep,
                                              uint8_t* buffer, uint16_t bufferSize);

np_error_code nc_client_connection_dispatch_close_connection(struct nc_client_connection_dispatch_context* ctx,
                                                          struct nc_client_connection* conn);


bool nc_client_connection_dispatch_validate_connection_id(struct nc_client_connection_dispatch_context* ctx, const uint8_t* connectionId);

#ifdef __cplusplus
} // extern c
#endif

#endif
