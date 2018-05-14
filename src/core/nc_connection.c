#include "nc_connection.h"

// THIS IS FOR MALLOC AND FREE, SHOULD BE REMOVED WITH ACTUAL IMPLEMENTATION
#include <stdlib.h>

struct np_connection {
    np_udp_socket* sock;
    np_connection_created_callback createCb;
    void* createData;
    np_connection_sent_callback sentCb;
    void* sentData;
    np_connection_received_callback recvCb;
    void* recvData;
    np_connection_destroyed_callback desCb;
    void* desData;
};

void nc_connection_init(struct np_connection_module* conn)
{
    conn->async_create = &nc_connection_async_create;
    conn->async_send_to = &nc_connection_async_send_to;
    conn->async_recv_from = &nc_connection_async_recv_from;
    conn->async_destroy = &nc_connection_async_destroy;
}

void createdCb(const np_error_code ec, np_udp_socket* socket, void* data)
{
    np_connection* conn = (np_connection*)data;
    conn->sock = socket;
    conn->createCb(ec, conn, conn->createData);
}

void sentCb(const np_error_code ec, void* data)
{
    np_connection* conn = (np_connection*)data;
    conn->sentCb(ec, conn->sentData);
}

void recvCb(const np_error_code ec, struct np_udp_endpoint ep, np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    np_connection* conn = (np_connection*)data;
    conn->recvCb(ec, conn, buffer, bufferSize, conn->recvData);
}

void destroyedCb(const np_error_code ec, void* data) {
    np_connection* conn = (np_connection*)data;
    np_connection_destroyed_callback cb = conn->desCb;
    void* d = conn->desData;
    // FREE SHOULD BE REMOVED WITH ACTUAL IMPLEMENTATION
    free(conn);
    cb(ec, d);
}

void nc_connection_async_create(struct np_platform* pl, np_connection_created_callback cb, void* data)
{
    // MALLOC SHOULD BE REMOVED WITH ACTUAL IMPLEMENTATION
    np_connection* conn = (np_connection*)malloc(sizeof(np_connection));
    conn->createCb = cb;
    conn->createData = data;
    pl->udp.async_create(createdCb, conn);
}

void nc_connection_async_send_to(struct np_platform* pl, np_connection* conn, struct np_udp_endpoint* ep, uint8_t* buffer, uint16_t bufferSize, np_connection_sent_callback cb, void* data)
{
    conn->sentCb = cb;
    conn->sentData = data;
    pl->udp.async_send_to(conn->sock, ep, buffer, bufferSize, sentCb, conn);
}

void nc_connection_async_recv_from(struct np_platform* pl, np_connection* conn, np_connection_received_callback cb, void* data)
{
    conn->recvCb = cb;
    conn->recvData = data;
    pl->udp.async_recv_from(conn->sock, recvCb, conn);
}

void nc_connection_async_destroy(struct np_platform* pl, np_connection* conn, np_connection_destroyed_callback cb, void* data)
{
    conn->desCb = cb;
    conn->desData = data;
    pl->udp.async_destroy(conn->sock, destroyedCb, conn);
}

