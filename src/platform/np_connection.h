#ifndef _NP_CONNECTION_H_
#define _NP_CONNECTION_H_

#include <platform/np_error_code.h>
#include <platform/np_platform.h>

typedef struct np_connection np_connection;

typedef void (*np_connection_created_callback)(const np_error_code ec, np_connection* conn, void* data);

typedef void (*np_connection_sent_callback)(const np_error_code ec, void* data);

typedef void (*np_connection_received_callback)(const np_error_code ec, struct np_connection* conn, np_communication_buffer* buffer, uint16_t bufferSize, void* data);

typedef void (*np_connection_destroyed_callback)(const np_error_code ec, void* data);

struct np_connection_module {
    /** 
     * Connection is currently a thin wrapper for the udp module, and
     * the interface is thereafter. Connections should be created for
     * a dns endpoint instead of providing a udp_endpoint when sending
     * data. 
     */
    void (*async_create)(struct np_platform* pl, np_connection_created_callback cb, void* data);
    void (*async_send_to)(struct np_platform* pl, np_connection* conn, struct np_udp_endpoint* ep, uint8_t* buffer, uint16_t bufferSize, np_connection_sent_callback cb, void* data);
    void (*async_recv_from)(struct np_platform* pl, np_connection* conn, np_connection_received_callback cb, void* data);
    void (*async_destroy)(struct np_platform* pl, np_connection* conn, np_connection_destroyed_callback cb, void* data);
};

#endif //_NP_CONNNECTION_H_
