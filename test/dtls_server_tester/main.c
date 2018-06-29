#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/udp/epoll/nm_epoll.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <modules/logging/nm_unix_logging.h>
#include <modules/timestamp/nm_unix_timestamp.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <platform/np_ip_address.h>
#include <platform/np_connection.h>
#include <core/nc_connection.h>
#include <core/nc_client_connect.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

struct test_context {
    int data;
    struct np_connection conn;
    np_udp_socket* sock;
    struct np_connection_channel channel;
    np_dtls_srv_connection* dtls;
    struct np_connection_id id;
};

struct np_platform pl;
struct np_timed_event ev;
struct np_timed_event closeEv;

void created(const np_error_code ec, uint8_t channelId, void* data)
{
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "created callback with FAILED");
        exit(1);
    }
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "Created, error code was: %i, and data: %i", ec, ctx->data);
    np_error_code ec2 = pl.dtlsS.create(&pl, &ctx->conn, ctx->dtls);
    if(ec2 != NABTO_EC_OK) {
        exit(1);
    }
}

void sockCreatedCb (const np_error_code ec, np_udp_socket* sock, void* data)
{
    struct test_context* ctx = (struct test_context*)data;
    ctx->sock = sock;
    ctx->channel.type = NABTO_CHANNEL_DTLS;
    ctx->channel.sock = sock;
    ctx->channel.ep.port = 0;
    ctx->channel.channelId = 0;
    pl.conn.async_create(&pl, &ctx->conn, &ctx->channel, &ctx->id, created, data);
}


int main() {
    np_platform_init(&pl);
    np_log.log = &nm_unix_log;
    np_log.log_buf = &nm_unix_log_buf;
    nm_unix_comm_buf_init(&pl);
    nm_epoll_init(&pl);
    nm_dtls_srv_init(&pl);
    nm_unix_ts_init(&pl);
    nc_client_connect_init(&pl);

    struct test_context data;
    data.data = 42;
    nc_connection_init(&pl);
    pl.udp.async_bind_port(4433, sockCreatedCb, &data);
    while (true) {
        np_event_queue_execute_all(&pl);
        NABTO_LOG_INFO(0, "before epoll wait %i", np_event_queue_has_ready_event(&pl));
        nm_epoll_wait();
    }

    exit(0);
}
