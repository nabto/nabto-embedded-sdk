#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/udp/epoll/nm_epoll.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <modules/logging/nm_unix_logging.h>
#include <modules/timestamp/nm_unix_timestamp.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <platform/np_ip_address.h>
#include <core/nc_client_connect.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

const char test_priv_key[] =
"-----BEGIN EC PARAMETERS-----\r\n"
"BggqhkjOPQMBBw==\r\n"
"-----END EC PARAMETERS-----\r\n"
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEIPwHCOmh7kIAFfGHK7C5QqJvY/MvXVJv2IGHayFZBDfMoAoGCCqGSM49\r\n"
"AwEHoUQDQgAE3STG13/95B6UFDiwjoVzKCj3rAIaEZIy9nelN8yyZEc654vepzk3\r\n"
"jL1pjCx4mgM/5xCqxFI0ctHZehFkmZrInQ==\r\n"
"-----END EC PRIVATE KEY-----\r\n";

const char test_pub_key_crt[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIB7TCCAZSgAwIBAgIJAK9g+0WW5dPhMAoGCCqGSM49BAMCMFIxCzAJBgNVBAYT\r\n"
"AkRLMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn\r\n"
"aXRzIFB0eSBMdGQxCzAJBgNVBAMMAk1NMB4XDTE4MDUwNDA4MzQwMVoXDTIwMDUw\r\n"
"MzA4MzQwMVowUjELMAkGA1UEBhMCREsxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf\r\n"
"BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDELMAkGA1UEAwwCTU0wWTAT\r\n"
"BgcqhkjOPQIBBggqhkjOPQMBBwNCAATdJMbXf/3kHpQUOLCOhXMoKPesAhoRkjL2\r\n"
"d6U3zLJkRzrni96nOTeMvWmMLHiaAz/nEKrEUjRy0dl6EWSZmsido1MwUTAdBgNV\r\n"
"HQ4EFgQUCx61qb7QZCunFl16Lr9Yszx07OgwHwYDVR0jBBgwFoAUCx61qb7QZCun\r\n"
"Fl16Lr9Yszx07OgwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiB9\r\n"
"oh2pYe+WgV6I+bV8LIiexQlgXZjh/ZEjds1TCuHAGQIgAsQ6zTkvEMy/1d6cU4FB\r\n"
"HB2dRWSdQGN3E4gle5w5/dg=\r\n"
"-----END CERTIFICATE-----\r\n";

struct test_context {
    int data;
    np_udp_socket* sock;
    struct np_dtls_srv_connection* dtls;
    struct nc_connection_id id;
};

struct np_platform pl;
struct np_timed_event ev;
struct np_timed_event closeEv;

void closeCb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(0, "DTLS connection closed");
    exit(0);
}

void recvedCb(const np_error_code ec, uint8_t channelId, uint64_t sequence,
            np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "RECEIVED CB");
    pl.dtlsS.async_close(&pl, ctx->dtls, closeCb, data);
}
void dtls_send_listener(uint8_t channelId, np_communication_buffer* buffer, uint16_t bufferSize, np_dtls_srv_send_callback cb, void* data, void* listenerData){
    // TODO: send the dtls data somewhere find a way to use the UDP socket without client_connect_dispatch
}

void created(const np_error_code ec, uint8_t channelId, void* data)
{
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "created callback with FAILED");
        exit(1);
    }
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "Created, error code was: %i, and data: %i", ec, ctx->data);
    NABTO_LOG_TRACE(0, "ctx->dtls: %u", ctx->dtls);
    np_error_code ec2 = pl.dtlsS.create(&pl, &ctx->dtls, &dtls_send_listener, ctx);
    NABTO_LOG_TRACE(0, "ctx->dtls: %u", ctx->dtls);
    pl.dtlsS.async_recv_from(&pl, ctx->dtls, AT_STREAM, recvedCb, ctx);
    if(ec2 != NABTO_EC_OK) {
        exit(1);
    }
}

void sockCreatedCb (const np_error_code ec, np_udp_socket* sock, void* data)
{
    struct test_context* ctx = (struct test_context*)data;
    ctx->sock = sock;
//    created(NABTO_EC_OK, 0, data);
    return;
}


int main() {
    uint8_t fp[16];
    memset(fp, 0, 16);

    np_platform_init(&pl);
    np_log.log = &nm_unix_log;
    np_log.log_buf = &nm_unix_log_buf;
    nm_unix_comm_buf_init(&pl);
    nm_epoll_init(&pl);
    nm_dtls_srv_init(&pl, (const unsigned char*)test_pub_key_crt, strlen(test_pub_key_crt), (const unsigned char*)test_priv_key, strlen(test_priv_key));
    nm_unix_ts_init(&pl);

    struct test_context data;
    data.data = 42;
    pl.udp.async_bind_port(4433, sockCreatedCb, &data);
    while (true) {
        np_event_queue_execute_all(&pl);
        NABTO_LOG_INFO(0, "before epoll wait %i", np_event_queue_has_ready_event(&pl));
        nm_epoll_wait();
    }

    exit(0);
}
