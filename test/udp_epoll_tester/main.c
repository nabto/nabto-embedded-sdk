#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/udp/epoll/nm_epoll.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <modules/logging/nm_unix_logging.h>
#include <modules/timestamp/nm_unix_timestamp.h>
#include <modules/dns/nm_unix_dns.h>
#include <platform/np_ip_address.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

struct test_context {
    np_udp_socket* sock;
    int data;
};
struct np_platform pl;
char string[] = "+Hello world";
np_communication_buffer* buffer;
uint16_t bufferSize = 13;
struct np_udp_endpoint ep;
struct np_timed_event ev;

void sent_callback(const np_error_code ec, void* data)
{
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "sent, error code was: %i, and data: %i", ec, ctx->data);
}

void packet_sender(const np_error_code ec, void* data)
{
    struct test_context* ctx = (struct test_context*) data;
    pl.udp.async_send_to(ctx->sock, &ep, buffer, bufferSize, &sent_callback, data);
    np_event_queue_post_timed_event(&pl, &ev, 2000, &packet_sender, data);
}

void recv_callback(const np_error_code ec, struct np_udp_endpoint ep, np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "Received: %s, with error code: %i", pl.buf.start(buffer), ec);
    pl.udp.async_recv_from(ctx->sock, &recv_callback, data);
}

void created(const np_error_code ec, np_udp_socket* socket, void* data)
{
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "Created, error code was: %i, and data: %i", ec, ctx->data);
    ctx->sock = socket;
    packet_sender(NABTO_EC_OK, ctx);
    pl.udp.async_recv_from(socket, &recv_callback, data);
}

void destroyed(const np_error_code ec, void* data) {
    struct test_context* ctx = (struct test_context*) data;
    ctx->sock = NULL;
    NABTO_LOG_INFO(0, "Destroyed, error code was: %i, and data: %i", ec, ctx->data);
}

void dns_resolved(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data)
{
    struct test_context* d = (struct test_context*) data;
    NABTO_LOG_INFO(0, "dns callback received with: ec: %i, recSize: %i, data.data: %i",ec, recSize, d->data);
    for (int i = 0; i < recSize; i++) {
        if (rec[i].type == NABTO_IPV4) {
            NABTO_LOG_INFO(0, PRIip4, MAKE_IPV4_PRINTABLE(rec[i].v4.addr));
        } else {
            NABTO_LOG_INFO(0, PRIip6, MAKE_IPV6_PRINTABLE(rec[i].v6.addr));
        }
    }
}

int main() {
    int nfds;
//    ep.port = 12345;
    ep.port = 4242;
    inet_pton(AF_INET6, "::1", ep.ip.v6.addr);
    NABTO_LOG_INFO(0, "pl: %i", &pl);
    np_platform_init(&pl);
    nm_unix_comm_buf_init(&pl);
    nm_epoll_init(&pl);
    nm_unix_ts_init(&pl);
    nm_unix_dns_init(&pl);

    np_log.log = &nm_unix_log;
    struct test_context data;
    data.data = 42;
    buffer = pl.buf.allocate();
    memcpy(pl.buf.start(buffer), string, strlen(string));
    pl.udp.async_create(created, &data);
    pl.dns.async_resolve(&pl, "www.google.com", &dns_resolved, &data);
    while (true) {
        np_event_queue_execute_all(&pl);
        if (np_event_queue_has_timed_event(&pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&pl);
            nfds = nm_epoll_wait(ms);
        } else {
            nfds = nm_epoll_wait(0);
        }
        nm_epoll_read(nfds);
    }

//    pl.udp.async_destroy(data.sock, destroyed, &data);
//    np_event_queue_poll_one(&pl);

    exit(0);
}
