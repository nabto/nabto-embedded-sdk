#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <platform/np_dtls_srv.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <platform/np_ip_address.h>
#include <core/nc_client_connection.h>
#include <test_platform/test_platform.h>

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
    struct np_udp_socket* sock;
    struct np_dtls_srv* dtlsServer;
    struct np_dtls_srv_connection* dtls;
    struct nc_connection_id id;
};

struct udp_send_context {
    np_dtls_srv_send_callback cb;
    void* data;
};

struct np_platform* pl;
struct np_timed_event ev;
struct np_timed_event closeEv;
struct np_udp_endpoint ep;


void closeCb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(0, "DTLS connection closed");
    exit(0);
}

void dtlsSendCb(const np_error_code ec, void* data)
{
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "dtls send failed");
        exit(1);
    }
    struct np_dtls_srv_send_context* sendCtx = ( struct np_dtls_srv_send_context* ) data;
    free(sendCtx->buffer);
    free(sendCtx);
    NABTO_LOG_INFO(0, "DTLS packet sent");
}

void receivedCb(uint8_t channelId, uint64_t sequence,
                uint8_t* buffer, uint16_t bufferSize, void* data)
{
    struct test_context* ctx = (struct test_context*) data;
    NABTO_LOG_INFO(0, "Server Received data:");
    NABTO_LOG_BUF(0, buffer, bufferSize);
    uint8_t* sendBuf = malloc(1500);
    struct np_dtls_srv_send_context* sendCtx = malloc(sizeof(struct np_dtls_srv_send_context));
    memcpy(sendBuf, buffer, bufferSize);
    sendCtx->buffer = sendBuf;
    sendCtx->bufferSize = bufferSize;
    sendCtx->cb = &dtlsSendCb;
    sendCtx->data = sendCtx;
    pl->dtlsS.async_send_data(pl, ctx->dtls, sendCtx);
    //pl.dtlsS.async_close(&pl, ctx->dtls, closeCb, data);
}

void eventCb(enum np_dtls_srv_event event, void* data)
{
    if (event == NP_DTLS_SRV_EVENT_CLOSED) {
        NABTO_LOG_ERROR(0, "dtls connection closed");
        exit(1);
    }
}

void udpSendCb(const np_error_code ec, void* data)
{
    struct udp_send_context* udpSendCtx = (struct udp_send_context*) data;
    udpSendCtx->cb(ec, udpSendCtx->data);
    free(udpSendCtx);
}

np_error_code dtls_send_listener(uint8_t channelId, uint8_t* buffer, uint16_t bufferSize, np_dtls_srv_send_callback cb, void* data, void* listenerData){
    struct test_context* ctx =  (struct test_context*) listenerData;
    NABTO_LOG_INFO(0, "Dtls wants to send to udp");
    // TODO: send the dtls data somewhere find a way to use the UDP socket without client_connect_dispatch
    struct udp_send_context* udpSendCtx = malloc(sizeof(struct udp_send_context));
    udpSendCtx->cb = cb;
    udpSendCtx->data = data;
    return pl->udp.async_send_to(ctx->sock, ep, buffer, bufferSize, &udpSendCb, udpSendCtx);
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
    np_error_code ec2 = pl->dtlsS.create_connection(ctx->dtlsServer, &ctx->dtls, &dtls_send_listener, &receivedCb, &eventCb, ctx);
    NABTO_LOG_TRACE(0, "ctx->dtls: %u", ctx->dtls);
    if(ec2 != NABTO_EC_OK) {
        exit(1);
    }
}

void udpRecvCb(const np_error_code ec, struct np_udp_endpoint epLocal,
               uint8_t* buffer, uint16_t bufferSize, void* data)
{
    struct test_context* ctx = (struct test_context*)data;
    ep = epLocal;
    NABTO_LOG_INFO(0, "UDP received:");
    NABTO_LOG_BUF(0, buffer, bufferSize);
    pl->dtlsS.handle_packet(pl, ctx->dtls, 0, buffer, bufferSize);
    pl->udp.async_recv_from(ctx->sock, udpRecvCb, data);
}

void sockCreatedCb (const np_error_code ec, void* data)
{
    struct test_context* ctx = (struct test_context*)data;
    pl->udp.async_recv_from(ctx->sock, udpRecvCb, data);
    created(ec, 0, data);
    return;
}


int main() {
    struct test_platform tp;

    test_platform_init(&tp);
    pl = &tp.pl;

    uint8_t fp[16];
    memset(fp, 0, 16);

    struct test_context data;
    memset(&data, 0, sizeof(data));
    pl->dtlsS.create(pl, &data.dtlsServer);
    pl->dtlsS.set_keys(data.dtlsServer, (const unsigned char*)test_pub_key_crt, strlen(test_pub_key_crt), (const unsigned char*)test_priv_key, strlen(test_priv_key));

    data.data = 42;
    pl->udp.create(pl, &data.sock);
    pl->udp.async_bind_port(data.sock, 4439, sockCreatedCb, &data);

    test_platform_run(&tp);

    exit(0);
}
