
#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/udp/epoll/nm_epoll.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <modules/logging/nm_unix_logging.h>
#include <modules/timestamp/nm_unix_timestamp.h>
#include <modules/crypto/nm_dtls.h>
#include <platform/np_ip_address.h>
#include <core/nc_connection.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

struct test_context {
    int data;
    struct np_connection conn;
};
struct np_platform pl;
uint8_t buffer[] = "Hello world";
uint16_t bufferSize = 12;
struct np_udp_endpoint ep;
struct np_timed_event ev;

void connected(const np_error_code ec, np_crypto_context* ctx, void* data)
{
//    struct test_context* text_ctx = (struct test_context*) data;
    
}

void created(const np_error_code ec, void* data)
{
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "Created, error code was: %i, and data: %i", ec, ctx->data);
//    packet_sender(NABTO_EC_OK, ctx);
//    ctx->connMod.async_recv_from(socket, &recv_callback, data);
    pl.cryp.async_connect(&pl, &ctx->conn, &connected, data);
}


int main() {
    ep.port = 4433;
    inet_pton(AF_INET6, "::1", ep.ip.v6.addr);
    NABTO_LOG_INFO(0, "pl: %i", &pl);
    np_platform_init(&pl);
    nm_unix_comm_buf_init(&pl);
    nm_epoll_init(&pl);
    nm_dtls_init(&pl);
    nm_unix_ts_init(&pl);

    np_log.log = &nm_unix_log;
    struct test_context data;
    data.data = 42;
    nc_connection_init(&pl);
    pl.conn.async_create(&pl, &data.conn, &ep, created, &data);
    while (true) {
        np_event_queue_execute_all(&pl);
        nm_epoll_wait();
    }

    exit(0);
}
