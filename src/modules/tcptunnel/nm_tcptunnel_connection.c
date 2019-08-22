#include "nm_tcptunnel.h"

/**
 * Forward data from a nabto stream to a tcp connection
 */


static void start_tcp_read(struct nm_tcptunnel_connection* connection);
static void tcp_readen(np_error_code ec, size_t transferred, void* userData);
static void start_stream_write(struct nm_tcptunnel_connection* connection, size_t transferred);
static void stream_written(np_error_code ec, void* userData);

static void start_stream_read(struct nm_tcptunnel_connection* connection);
static void stream_readen(np_error_code ec, size_t transferred, void* userData);
static void start_tcp_write(struct nm_tcptunnel_connection* connection, size_t transferred);
static void tcp_written(np_error_code ec, void* userData);


void start_resolve()
{

}

void resolved()
{

}

void start_connect()
{

}

void connected()
{
    start_tcp_read();
    start_stream_read();
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
        close_tcp_connection(connection);
        return;
    }
    start_tcp_read(connection);
}

void start_stream_read(struct nm_tcptunnel_connection* connection)
{
    nc_stream_async_read(connection->stream, connection->streamRecvBuffer, connection->streamRecvBufferSize, &stream_readen, connection);
}

void stream_readen(np_error_code ec, size_t transferred, void* userData)
{
    struct nm_tcptunnel_connection* connection = userData;
    if (ec) {
        // TODO
    }
    if (transferred == 0 || ec == NABTO_EC_EOF) {
        // TODO close tcp connection, aka signal to the tcp connection
        // that we will not write more data.
    }
    start_tcp_write(connection, transferred);
}

void start_tcp_write(struct nm_tcptunnel_connection* connection, size_t transferred)
{
    struct np_platform* pl;
    pl->tcp.async_write(pl, connection->streamRecvBuffer, transferred, &tcp_written, connection);
}

void tcp_written(np_error_code ec, void* userData)
{
    struct nm_tcptunnel_connection* connection = userData;
    if (ec) {
        // TODO if ec, we cannot write to the tcp connection, close the stream
        nc_stream_close(connection->stream);
        return;
    }
    start_stream_read(connection);
}
