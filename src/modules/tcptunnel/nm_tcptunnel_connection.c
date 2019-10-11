#include "nm_tcptunnel.h"
#include <core/nc_stream.h>
#include <platform/np_logging.h>

#include <stdlib.h>

/**
 * Forward data from a nabto stream to a tcp connection
 */

static void start_connect(struct nm_tcptunnel_connection* connection);
static void connect_callback(np_error_code ec, void* userData);
static void connected(struct nm_tcptunnel_connection* connection);

static void start_tcp_read(struct nm_tcptunnel_connection* connection);
static void tcp_readen(np_error_code ec, size_t transferred, void* userData);
static void start_stream_write(struct nm_tcptunnel_connection* connection, size_t transferred);
static void stream_written(np_error_code ec, void* userData);
static void close_stream(struct nm_tcptunnel_connection* connection);
static void stream_closed(np_error_code ec, void* userDat);

static void start_stream_read(struct nm_tcptunnel_connection* connection);
static void stream_readen(np_error_code ec, void* userData);
static void start_tcp_write(struct nm_tcptunnel_connection* connection, size_t transferred);
static void tcp_written(np_error_code ec, void* userData);
static void close_tcp(struct nm_tcptunnel_connection* connection);

static void abort_connection(struct nm_tcptunnel_connection* connection);
static void is_ended(struct nm_tcptunnel_connection* connection);
static void the_end(struct nm_tcptunnel_connection* connection);

#define LOG NABTO_LOG_MODULE_TUNNEL

/**
 * called from the tunnel manager
 */
struct nm_tcptunnel_connection* nm_tcptunnel_connection_new()
{
    struct nm_tcptunnel_connection* connection = calloc(1,sizeof(struct nm_tcptunnel_connection));
    if (connection == NULL) {
        return NULL;
    }

    connection->tcpRecvBufferSize = NM_TCPTUNNEL_BUFFER_SIZE;
    connection->streamRecvBufferSize = NM_TCPTUNNEL_BUFFER_SIZE;
    return connection;
}

void nm_tcptunnel_connection_free(struct nm_tcptunnel_connection* connection)
{
    struct np_platform* pl = connection->pl;
    pl->tcp.destroy(connection->socket);
    if (connection->stream) {
        nc_stream_release(connection->stream);
    }
    free(connection);
}

np_error_code nm_tcptunnel_connection_init(struct nm_tcptunnel* tunnel, struct nm_tcptunnel_connection* connection, struct nc_stream_context* stream)
{
    connection->pl = tunnel->tunnels->device->pl;
    struct np_platform* pl = connection->pl;
    np_error_code ec = pl->tcp.create(pl, &connection->socket);
    if (ec) {
        NABTO_LOG_ERROR(LOG, "Cannot create tcp connection");
        return ec;
    }
    connection->stream = stream;

    connection->address = tunnel->address;
    connection->port = tunnel->port;


    // insert connection into back of connections list
    struct nm_tcptunnel_connection* before = tunnel->connectionsSentinel.prev;
    struct nm_tcptunnel_connection* after = &tunnel->connectionsSentinel;
    before->next = connection;
    connection->next = after;
    after->prev = connection;
    connection->prev = before;

    connection->tcpRecvBufferSize = NM_TCPTUNNEL_BUFFER_SIZE;
    connection->streamRecvBufferSize = NM_TCPTUNNEL_BUFFER_SIZE;
    connection->tcpReadEnded = false;
    connection->streamReadEnded = false;

    return NABTO_EC_OK;
}

void nm_tcptunnel_connection_start(struct nm_tcptunnel_connection* connection)
{
    // accept the stream
    nc_stream_accept(connection->stream);
    start_connect(connection);
}

/**
 * Called from manager when the tunnel is asked to close down.
 * Either because the underlying nabto connection is closed or the system is closing down.
 */
void nm_tcptunnel_connection_stop_from_manager(struct nm_tcptunnel_connection* connection)
{
    // Reset the tunnel reference as the tunnel manager has removed
    // the tunnel from its list of tunnels.
    // This will stop all async operations. That will lead to an error
    // or clean stop and the tunnel is going to be stopped and cleaned
    // up.
    abort_connection(connection);
//    nm_tcptunnel_connection_free(connection);
}


/**
 * Private functions
 */
void start_connect(struct nm_tcptunnel_connection* connection)
{
    struct np_platform* pl = connection->pl;
    pl->tcp.async_connect(connection->socket, &connection->address, connection->port, &connect_callback, connection);
}

void connect_callback(np_error_code ec, void* userData)
{
    struct nm_tcptunnel_connection* connection = userData;
    if (ec) {
        NABTO_LOG_ERROR(LOG, "Could not connect to tcp endpoint");
        the_end(connection);
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
    if (transferred == 0 || ec == NABTO_EC_EOF) {
        NABTO_LOG_TRACE(LOG, "TCP EOF received");
        // Close stream, aka signal that we will not write any
        // more data to the stream.
        return close_stream(connection);
    }
    if (ec) {
        NABTO_LOG_ERROR(LOG, "Tcp read error");
        // something not EOF
        connection->tcpReadEnded = true;
        return abort_connection(connection);
    }
    start_stream_write(connection, transferred);
}

void close_stream(struct nm_tcptunnel_connection* connection)
{
    nc_stream_async_close(connection->stream, &stream_closed, connection);
}

void stream_closed(np_error_code ec, void* userData)
{
    struct nm_tcptunnel_connection* connection = userData;
    connection->tcpReadEnded = true;
    is_ended(connection);
}

void start_stream_write(struct nm_tcptunnel_connection* connection, size_t transferred)
{
    nc_stream_async_write(connection->stream, connection->tcpRecvBuffer, transferred, &stream_written, connection);
}

void stream_written(np_error_code ec, void* userData)
{
    struct nm_tcptunnel_connection* connection = userData;
    if (ec) {
        NABTO_LOG_ERROR(LOG, "Stream write failed, stopping the tcp tunnel connection");
        // failed to write the data to the stream. In this scenario we
        // need to fail the connection since we cannot guarantee the
        // data was delivered.
        connection->tcpReadEnded = true;
        abort_connection(connection);
        is_ended(connection);
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
    if (connection->streamReadSize == 0 || ec == NABTO_EC_EOF) {
        NABTO_LOG_TRACE(LOG, "tcp tunnel stream read EOF.");
        return close_tcp(connection);
    }
    if (ec) {
        NABTO_LOG_ERROR(LOG, "tcp tunnel, stream read failed stopping the tcp tunnel connection");
        connection->streamReadEnded = true;
        abort_connection(connection);
        is_ended(connection);
        return;
    }

    start_tcp_write(connection, connection->streamReadSize);
}

void close_tcp(struct nm_tcptunnel_connection* connection)
{
    struct np_platform* pl = connection->pl;
    // inform tcp that no more data is written to the socket.
    pl->tcp.shutdown(connection->socket);
    connection->streamReadEnded = true;
    is_ended(connection);
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
        NABTO_LOG_ERROR(LOG, "Could not write all the data to the tcp connection, closing the tcp tunnel connection");
        // unrecoverable error
        connection->streamReadEnded = true;
        abort_connection(connection);
        is_ended(connection);
        return;
    }
    start_stream_read(connection);
}

void abort_connection(struct nm_tcptunnel_connection* connection)
{
    // close stream and tcp and end it all.
    struct np_platform* pl = connection->pl;
    pl->tcp.close(connection->socket);
    if (connection->stream) {
        nc_stream_abort(connection->stream);
        connection->stream = NULL;
    }
}

void is_ended(struct nm_tcptunnel_connection* connection)
{
    if (connection->tcpReadEnded && connection->streamReadEnded) {
        NABTO_LOG_TRACE(LOG, "Both tcp and stream read has ended");
        the_end(connection);
    }
}

/**
 * Called when all async operations has ended.
 */
void the_end(struct nm_tcptunnel_connection* connection)
{
    if (connection->next != NULL &&
        connection->prev != NULL)
    {
        nm_tcptunnel_remove_connection(connection);
    }
    nm_tcptunnel_connection_free(connection);
}
