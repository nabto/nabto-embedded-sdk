#include "nm_tcptunnel.h"
#include <core/nc_stream.h>

#include <stdlib.h>

/**
 * Forward data from a nabto stream to a tcp connection
 */

static void stream_accepted(const np_error_code ec, void* userData);
static void start_connect(struct nm_tcptunnel_connection* connection);
static void connect_callback(np_error_code ec, void* userData);
static void connected(struct nm_tcptunnel_connection* connection);

static void start_tcp_read(struct nm_tcptunnel_connection* connection);
static void tcp_readen(np_error_code ec, size_t transferred, void* userData);
static void start_stream_write(struct nm_tcptunnel_connection* connection, size_t transferred);
static void stream_written(np_error_code ec, void* userData);

static void start_stream_read(struct nm_tcptunnel_connection* connection);
static void stream_readen(np_error_code ec, void* userData);
static void start_tcp_write(struct nm_tcptunnel_connection* connection, size_t transferred);
static void tcp_written(np_error_code ec, void* userData);


struct nm_tcptunnel_connection* nm_tcptunnel_connection_new()
{
    struct nm_tcptunnel_connection* connection = calloc(1,sizeof(struct nm_tcptunnel_connection));
    if (connection == NULL) {
        return NULL;
    }

    connection->tcpRecvBufferSize = 1024;
    connection->streamRecvBufferSize = 1024;
    return connection;
}

void nm_tcptunnel_connection_free(struct nm_tcptunnel_connection* connection)
{
    // TODO
    free(connection);
}

np_error_code nm_tcptunnel_connection_init(struct nm_tcptunnel* tunnel, struct nm_tcptunnel_connection* connection, struct nc_stream_context* stream)
{
    connection->tunnel = tunnel;
    connection->pl = tunnel->tunnels->device->pl;
    struct np_platform* pl = connection->pl;
    np_error_code ec = pl->tcp.create(pl, &connection->socket);
    if (ec) {
        return ec;
    }
    connection->stream = stream;


    // insert connection into back of connections list
    struct nm_tcptunnel_connection* before = tunnel->connectionsSentinel.prev;
    struct nm_tcptunnel_connection* after = &tunnel->connectionsSentinel;
    before->next = connection;
    connection->next = after;
    after->prev = connection;
    connection->prev = before;

    connection->tcpRecvBufferSize = 1024;
    connection->streamRecvBufferSize = 1024;

    return NABTO_EC_OK;
}

void nm_tcptunnel_connection_start(struct nm_tcptunnel_connection* connection)
{
    // accept the stream
    np_error_code ec = nc_stream_async_accept(connection->stream, &stream_accepted, connection);
    if (ec) {
        // handle accept failed
    }
}

void stream_accepted(const np_error_code ec, void* userData)
{
    struct nm_tcptunnel_connection* connection = userData;
    if (ec) {
        // TODO handle accept failed
    }
    start_connect(connection);
}

void start_connect(struct nm_tcptunnel_connection* connection)
{
    struct np_platform* pl = connection->pl;
    struct nm_tcptunnel* tunnel = connection->tunnel;
    pl->tcp.async_connect(connection->socket, &tunnel->address, tunnel->port, &connect_callback, connection);
}

void connect_callback(np_error_code ec, void* userData)
{
    struct nm_tcptunnel_connection* connection = userData;
    if (ec) {
        // TODO fail tunnel
        return;
    }
    connected(connection);
}

void connected(struct nm_tcptunnel_connection* connection)
{
    start_tcp_read(connection);
    start_stream_read(connection);
}


void start_tcp_read(struct nm_tcptunnel_connection* connection)
{
    struct np_platform* pl = connection->pl;
    pl->tcp.async_read(connection->socket, connection->tcpRecvBuffer, connection->tcpRecvBufferSize, &tcp_readen, connection);
}

void tcp_readen(np_error_code ec, size_t transferred, void* userData)
{
    struct nm_tcptunnel_connection* connection = userData;
    if (ec) {
        // TODO
    }
    if (transferred == 0 || ec == NABTO_EC_EOF) {
        // TODO close stream, aka signal that we will not write any
        // more data to the stream.
    }
    start_stream_write(connection, transferred);
}

void start_stream_write(struct nm_tcptunnel_connection* connection, size_t transferred)
{
    nc_stream_async_write(connection->stream, connection->tcpRecvBuffer, transferred, &stream_written, connection);
}

void stream_written(np_error_code ec, void* userData)
{
    struct nm_tcptunnel_connection* connection = userData;
    if (ec) {
        // TODO if stream write fails, close the tcp connection, the stream has already failed.
        //close_tcp_connection(connection);
        return;
    }
    start_tcp_read(connection);
}

void start_stream_read(struct nm_tcptunnel_connection* connection)
{
    nc_stream_async_read_some(connection->stream, connection->streamRecvBuffer, connection->streamRecvBufferSize, &connection->streamReadSize, &stream_readen, connection);
}

void stream_readen(np_error_code ec, void* userData)
{
    struct nm_tcptunnel_connection* connection = userData;
    if (ec) {
        // TODO
    }
    if (connection->streamReadSize == 0 || ec == NABTO_EC_EOF) {
        // TODO close tcp connection, aka signal to the tcp connection
        // that we will not write more data.
    }
    start_tcp_write(connection, connection->streamReadSize);
}

void start_tcp_write(struct nm_tcptunnel_connection* connection, size_t transferred)
{
    struct np_platform* pl = connection->pl;
    pl->tcp.async_write(connection->socket, connection->streamRecvBuffer, transferred, &tcp_written, connection);
}

void tcp_written(np_error_code ec, void* userData)
{
    struct nm_tcptunnel_connection* connection = userData;
    if (ec) {
        // TODO if ec, we cannot write to the tcp connection, close the stream
        //nc_stream_close(connection->stream);
        return;
    }
    start_stream_read(connection);
}
