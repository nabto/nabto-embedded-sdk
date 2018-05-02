#include <platform/platform.h>
#include <platform/logging.h>
#include <modules/udp/epoll/nm_epoll.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <modules/logging/unix_logging.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

struct test_context {
    nabto_udp_socket* sock;
    int data;
};
struct nabto_platform pl;
uint8_t buffer[] = "Hello world";
uint16_t bufferSize = 12;
struct nabto_udp_endpoint ep;
struct nabto_timed_event ev;

void sent_callback(const nabto_error_code ec, void* data)
{
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "sent, error code was: %i, and data: %i", ec, ctx->data);
}

void packet_sender(const nabto_error_code ec, void* data)
{
    struct test_context* ctx = (struct test_context*) data;
    pl.udp.async_send_to(ctx->sock, &ep, buffer, bufferSize, &sent_callback, data);
    nabto_event_queue_post_timed_event(&pl, &ev, 2000, &packet_sender, data);
}

void recv_callback(const nabto_error_code ec, struct nabto_udp_endpoint ep, nabto_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "Received: %s, with error code: %i", pl.buf.start(buffer), ec);
    pl.udp.async_recv_from(ctx->sock, &recv_callback, data);
}

void created(const nabto_error_code ec, nabto_udp_socket* socket, void* data){
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "Created, error code was: %i, and data: %i", ec, ctx->data);
    ctx->sock = socket;
    packet_sender(NABTO_EC_OK, ctx);
    pl.udp.async_recv_from(socket, &recv_callback, data);
}

void destroyed(const nabto_error_code ec, void* data) {
    struct test_context* ctx = (struct test_context*) data;
    ctx->sock = NULL;
    NABTO_LOG_INFO(0, "Destroyed, error code was: %i, and data: %i", ec, ctx->data);
}

nabto_timestamp time;
bool ts_passed_or_now(nabto_timestamp* timestamp)
{
    return (time >= *timestamp);
}

void ts_now(nabto_timestamp* ts)
{
    *ts = time;
}
bool ts_less_or_equal(nabto_timestamp* t1, nabto_timestamp* t2)
{
    return (*t1 <= *t2);
}

void ts_set_future_timestamp(nabto_timestamp* ts, uint32_t milliseconds)
{
    *ts = time + milliseconds;
}

uint32_t ts_difference(nabto_timestamp* ts1, nabto_timestamp* ts2)
{
    return *ts1-*ts2;
}


int main() {
    ep.port = 12345;
    inet_pton(AF_INET6, "::1", ep.ip.v6.addr);
    NABTO_LOG_INFO(0, "pl: %i", &pl);
    nabto_platform_init(&pl);
    nm_unix_comm_buf_init(&pl);
    nm_epoll_init(&pl);
    pl.ts.passed_or_now = &ts_passed_or_now;
    pl.ts.less_or_equal = &ts_less_or_equal;
    pl.ts.now = &ts_now;
    pl.ts.set_future_timestamp = &ts_set_future_timestamp;
    pl.ts.difference = &ts_difference;
 
    nabto_log.log = &unix_log;
    struct test_context data;
    data.data = 42;
    pl.udp.async_create(created, &data);

    time = 0;
    while (true) {
        while (!nabto_event_queue_is_event_queue_empty(&pl)) {
            nabto_event_queue_poll_one(&pl);
        }
        while (nabto_event_queue_has_ready_timed_event(&pl)) {
            nabto_event_queue_poll_one_timed_event(&pl);
        }
        nm_epoll_wait();
        time = time + 1000;
    }

//    pl.udp.async_destroy(data.sock, destroyed, &data);
//    nabto_event_queue_poll_one(&pl);

    exit(0);
}
