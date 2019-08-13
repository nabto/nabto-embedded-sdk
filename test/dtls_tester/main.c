#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <platform/np_ip_address.h>
#include <core/nc_client_connection.h>
#include <core/nc_udp_dispatch.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

const unsigned char devicePrivateKey[] =
"-----BEGIN EC PARAMETERS-----\r\n"
"BggqhkjOPQMBBw==\r\n"
"-----END EC PARAMETERS-----\r\n"
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEII2ifv12piNfHQd0kx/8oA2u7MkmnQ+f8t/uvHQvr5wOoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEY1JranqmEwvsv2GK5OukVPhcjeOW+MRiLCpy7Xdpdcdc7he2nQgh\r\n"
"0+aTVTYvHZWacrSTZFQjXljtQBeuJR/Gsg==\r\n"
"-----END EC PRIVATE KEY-----\r\n";

const unsigned char devicePublicKey[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIBaTCCARCgAwIBAgIJAOR5U6FNgvivMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMM\r\n"
"BW5hYnRvMB4XDTE4MDgwNzA2MzgyN1oXDTQ4MDczMDA2MzgyN1owEDEOMAwGA1UE\r\n"
"AwwFbmFidG8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARjUmtqeqYTC+y/YYrk\r\n"
"66RU+FyN45b4xGIsKnLtd2l1x1zuF7adCCHT5pNVNi8dlZpytJNkVCNeWO1AF64l\r\n"
"H8ayo1MwUTAdBgNVHQ4EFgQUjq36vzjxAQ7I8bMejCf1/m0eQ2YwHwYDVR0jBBgw\r\n"
"FoAUjq36vzjxAQ7I8bMejCf1/m0eQ2YwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO\r\n"
"PQQDAgNHADBEAiBF98p5zJ+98XRwIyvCJ0vcHy/eJM77fYGcg3J/aW+lIgIgMMu4\r\n"
"XndF4oYF4h6yysELSJfuiamVURjo+KcM1ixwAWo=\r\n"
"-----END CERTIFICATE-----\r\n";

struct test_context {
    int data;
    struct nc_udp_dispatch_context udp;
    struct nc_connection_id id;
    np_dtls_cli_context* dtlsClient;
};
struct np_platform pl;
uint8_t buffer[] = "Hello world";
uint16_t bufferSize = 12;
struct np_udp_endpoint ep;
struct np_timed_event ev;
struct np_timed_event ev2;
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

void mainRecvCb(const np_error_code ec, uint8_t channelId, uint64_t sequence, np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
//    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    NABTO_LOG_INFO(0, "Received rec callback with ec: %i, and data: %s", ec, pl.buf.start(buffer));
//    pl.dtlsC.async_close(&pl, ctx, &closeCb, NULL);
}

void echo(const np_error_code ec, void* data)
{
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "echo with FAILED status");
        exit(1);
    }
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    pl.dtlsC.async_send_to(&pl, ctx, 0xff, buffer, bufferSize, &sendCb, data);
    pl.dtlsC.async_recv_from(&pl, ctx, &mainRecvCb, data);
    np_event_queue_post_timed_event(&pl, &ev, 1000, &echo, data);
}

void echo2(const np_error_code ec, void* data)
{
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "echo with FAILED status");
        exit(1);
    }
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    pl.dtlsC.async_send_to(&pl, ctx, 0xff, buffer, bufferSize, &sendCb, data);
    pl.dtlsC.async_recv_from(&pl, ctx, &mainRecvCb, data);
    np_event_queue_post_timed_event(&pl, &ev2, 1000, &echo2, data);
}

void connected(const np_error_code ec, np_dtls_cli_context* ctx, void* data)
{
    echo(ec, ctx);
    echo2(ec, ctx);
    NABTO_LOG_INFO(0, "CONNECTION ESTABLISHED!!");
}

void created(const np_error_code ec, uint8_t channelId, void* data)
{
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "created callback with FAILED");
        exit(1);
    }
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "Created, error code was: %i, and data: %i", ec, ctx->data);
    nc_udp_dispatch_set_dtls_cli_context(&ctx->udp, ctx->dtlsClient);
    pl.dtlsC.async_connect(&pl, ctx->dtlsClient, &ctx->udp, ep, connected, data);
}

void sockCreatedCb (const np_error_code ec, void* data)
{
    created(NABTO_EC_OK, 0, data);
    return;
}

int main() {
    int nfds;
    uint8_t fp[16];
    memset(fp, 0, 16);

    ep.port = 4439;
    inet_pton(AF_INET6, "::1", ep.ip.v6.addr);
    ep.ip.type = NABTO_IPV6;
    NABTO_LOG_INFO(0, "pl: %i", &pl);
    np_platform_init(&pl);
    np_communication_buffer_init(&pl);
    np_udp_init(&pl);
    np_dtls_cli_init(&pl);
    np_ts_init(&pl);

    np_log_init();
    struct test_context data;
    data.data = 42;
    nc_udp_dispatch_async_create(&data.udp, &pl, 0, sockCreatedCb, &data);

    data.dtlsClient = pl.dtlsC.create(&pl);
    pl.dtlsC.set_keys(data.dtlsClient, devicePublicKey, strlen((const char*)devicePublicKey), devicePrivateKey, strlen((const char*)devicePrivateKey));

    while (true) {
        np_event_queue_execute_all(&pl);
        NABTO_LOG_INFO(0, "before epoll wait %i", np_event_queue_has_ready_event(&pl));
        if (np_event_queue_has_timed_event(&pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&pl);
            nfds = pl.udp.timed_wait(ms);
        } else {
            nfds = pl.udp.inf_wait();
        }
        if (nfds > 0) {
            pl.udp.read(nfds);
        }
    }

    exit(0);
}
