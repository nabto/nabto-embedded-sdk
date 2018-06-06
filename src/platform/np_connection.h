#ifndef _NP_CONNECTION_H_
#define _NP_CONNECTION_H_

#include <platform/np_error_code.h>
#include <platform/np_event_queue.h>
#include <platform/np_platform.h>

typedef struct np_connection np_connection;

typedef void (*np_connection_created_callback)(const np_error_code ec, void* data);

typedef void (*np_connection_sent_callback)(const np_error_code ec, void* data);

typedef void (*np_connection_received_callback)(const np_error_code ec, struct np_connection* conn, np_communication_buffer* buffer, uint16_t bufferSize, void* data);

typedef void (*np_connection_destroyed_callback)(const np_error_code ec, void* data);

struct np_connection {
    np_udp_socket* sock;
    struct np_udp_endpoint ep;
    struct np_event ev;
    np_connection_created_callback createCb;
    void* createData;
    np_connection_sent_callback sentCb;
    void* sentData;
    np_connection_received_callback recvCb;
    void* recvData;
    np_connection_destroyed_callback desCb;
    void* desData;
};

struct np_connection_module {
    /** 
     * Connection is currently a thin wrapper for the udp module, and
     * the interface is thereafter.
     */
    void (*async_create)(struct np_platform* pl, np_connection* conn, np_udp_socket* sock, struct np_udp_endpoint* ep, np_connection_created_callback cb, void* data);
    void (*async_send_to)(struct np_platform* pl, np_connection* conn, uint8_t* buffer, uint16_t bufferSize, np_connection_sent_callback cb, void* data);
    void (*async_recv_from)(struct np_platform* pl, np_connection* conn, np_connection_received_callback cb, void* data);
    np_error_code (*cancel_async_recv)(struct np_platform* pl, np_connection* conn);
    void (*async_destroy)(struct np_platform* pl, np_connection* conn, np_connection_destroyed_callback cb, void* data);
};

#endif //_NP_CONNNECTION_H_
