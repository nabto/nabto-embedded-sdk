#ifndef NC_CONNECTION_H
#define NC_CONNECTION_H

#include <nabto/nabto_device_config.h>

#include <core/nc_coap_server.h>
#include <platform/np_platform.h>

#include <core/nc_connection_event.h>
#include <core/nc_spake2.h>

#ifdef __cplusplus
extern "C" {
#endif


struct nc_device_context;

typedef void (*nc_connections_close_callback)(void* data);


struct nc_connection {
    void* connectionImplCtx;
    struct nc_device_context* device;
    uint64_t connectionRef;
    bool isVirtual;
    struct nn_llist_node connectionsNode;
#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
    bool hasSpake2Key;  // true iff the key has been set
    uint8_t spake2Key[32];
    bool passwordAuthenticated; // true iff some password authentication request has succeeded on the connection.
    char* username; // username used for password authentication if passwordAuthentication was attempted
#endif
};

struct nc_connections_context {
    struct nn_llist connections;
    size_t maxConcurrentConnections;
    size_t currentConnections;
    nc_connections_close_callback closeCb;
    void* closeData;
    bool closing;
    struct nc_device_context* device;

};


np_error_code nc_connections_init(struct nc_connections_context* ctx, struct nc_device_context* device);
void nc_connections_deinit(struct nc_connections_context* ctx);
np_error_code nc_connections_async_close(struct nc_connections_context* ctx, nc_connections_close_callback cb, void* data);
struct nc_connection* nc_connections_alloc_client_connection(struct nc_connections_context* ctx);
struct nc_connection* nc_connections_alloc_virtual_connection(struct nc_connections_context* ctx);
struct nc_connection* nc_connections_connection_from_ref(struct nc_connections_context* ctx, uint64_t ref);
struct nc_connection* nc_connections_connection_from_id(struct nc_connections_context* ctx, const uint8_t* id);
struct nc_connection* nc_connections_connection_from_client_connection(struct nc_connections_context* ctx, struct nc_client_connection* cliConn);
size_t nc_connections_count_connections(struct nc_connections_context* ctx);
void nc_connections_free_connection(struct nc_connections_context* ctx, struct nc_connection* connection);

/**
 * Initialize a connection obejct.
 * If isVirtual is false, impl must be an nc_client_connection
 * If isVirtual is true, impl must be an nc_virtual_connection
 */
np_error_code nc_connection_init(struct nc_connection* conn, struct nc_device_context* device, bool isVirtual, void* impl);

/**
 * Get client fingerprint of a connection.
 * If a client_connection, this is the fingerprint from DTLS
 * If a virtual_connection, this is set through the API
 * If a virtual_connection, but fp not set false is returned
 */
bool nc_connection_get_client_fingerprint(struct nc_connection* connection, uint8_t* fp);

/**
 * Get device fingerprint of a connection.
 * If a client_connection, this is the fingerprint the DTLS device key
 * If a virtual_connection, this is set through the API
 * If a virtual_connection, but fp not set false is returned
 */
bool nc_connection_get_device_fingerprint(struct nc_connection* connection, uint8_t* fp);

/**
 * Query if connection uses local socket or not. Used by API.
 */
bool nc_connection_is_local(struct nc_connection* conn);

/**
 * Query if the connection is password authenticated or not. Used by API.
 */
bool nc_connection_is_password_authenticated(struct nc_connection* conn);

/**
 * Query if connection is virtual or not. Used by API.
 */
bool nc_connection_is_virtual(struct nc_connection* conn);

/**
 * internal only called from self. Notifies nc_device of events.
 */
void nc_connection_events_listener_notify(struct nc_connection* conn, enum nc_connection_event event);

#ifdef __cplusplus
} // extern c
#endif

#endif
