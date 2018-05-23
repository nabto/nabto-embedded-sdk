
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
struct np_timed_event closeEv;

void exitter(const np_error_code ec, void* data)
{
    exit(0);
}

void closeCb(const np_error_code ec, void* data)
{
    np_event_queue_post_timed_event(&pl, &closeEv, 1000, &exitter, NULL);
}

void sendCb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(0, "Received send callback with ec: %i", ec);
}

void mainRecvCb(const np_error_code ec, np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    NABTO_LOG_INFO(0, "Received rec callback with ec: %i, and data: %s", ec, pl.buf.start(buffer));
    pl.cryp.async_close(&pl, ctx, &closeCb, NULL);
}

void echo(const np_error_code ec, void* data)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    pl.cryp.async_send_to(&pl, ctx, buffer, bufferSize, &sendCb, data);
    pl.cryp.async_recv_from(&pl, ctx, &mainRecvCb, data);
    np_event_queue_post_timed_event(&pl, &ev, 1000, &echo, data);
}

void connected(const np_error_code ec, np_crypto_context* ctx, void* data)
{
    echo(ec, ctx);
    NABTO_LOG_INFO(0, "CONNECTION ESTABLISHED!!");
}

void created(const np_error_code ec, void* data)
{
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "Created, error code was: %i, and data: %i", ec, ctx->data);
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
        NABTO_LOG_INFO(0, "before epoll wait %i", np_event_queue_has_ready_event(&pl));
        nm_epoll_wait();
    }

    exit(0);
}
