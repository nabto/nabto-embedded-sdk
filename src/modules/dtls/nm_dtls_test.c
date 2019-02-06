#include <nabto_types.h>
#include <platform/np_unit_test.h>
#include "nm_dtls_util.h"
#include "nm_dtls_cli.h"
#include "nm_dtls_srv.h"
#include <modules/communication_buffer/nm_unix_communication_buffer.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct np_test_system nts;
struct np_platform pl;

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
/**
 * extract fingerprint form shell
 *
 * openssl ec -in device.pem -pubout > devicepublickey.pem
 * openssl ec -pubin -in devicepublickey.pem -outform der > devicepublickey.der
 * sha256sum devicepublickey.der 
 * dd5fec4f27b5657cb75e5e247fe792cc096adc3670897660946278d67d9d95f7  devicepublickey.der
 *
 * short form: openssl ec -in device.pem -pubout -outform der | sha256sum
 * dd5fec4f27b5657cb75e5e247fe792cc096adc3670897660946278d67d9d95f7
 */


const char certFingerprint[] = { 0xdd, 0x5f, 0xec, 0x4f, 0x27, 0xb5, 0x65, 0x7c, 0xb7, 0x5e, 0x5e, 0x24, 0x7f, 0xe7, 0x92, 0xcc};


void test_dtls_connection();

void on_check_fail(const char* file, int line)
{
    printf("check failed: %s:%i\n", file, line);
}

int main() {
    nts.on_check_fail = on_check_fail;
    uint8_t fp[16];
    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    
    int status = mbedtls_x509_crt_parse(&chain, devicePublicKey, strlen((const char*)devicePublicKey)+1);
    NABTO_TEST_CHECK(status == 0);

    np_error_code ec = nm_dtls_util_fp_from_crt(&chain, fp);
    
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);

    NABTO_TEST_CHECK(memcmp(certFingerprint, fp, 16) == 0);

    test_dtls_connection();
    
    printf("%i errors, %i ok checks\n", nts.fail, nts.ok);
    if (nts.fail > 0) {
        exit(1);
    } else {
        exit(0);
    }
}
np_communication_buffer* cliSendBuf;
uint16_t cliSendBufSize;
np_communication_buffer* srvSendBuf;
uint16_t srvSendBufSize;
struct np_connection srvConn;
struct np_connection cliConn;

void test_async_send_to_server(void* data)
{
    if(cliSendBuf == NULL || srvConn.recvCb == NULL) {
        NABTO_TEST_CHECK(false);
    } else {
        np_connection_received_callback cb = srvConn.recvCb;
        srvConn.recvCb = NULL;
        cb(NABTO_EC_OK, &srvConn, 0, cliSendBuf, cliSendBufSize, srvConn.recvData);
        cliSendBuf = NULL;
        cliConn.sentCb(NABTO_EC_OK, cliConn.sentData);
    }
}

void test_async_send_to_client(void* data)
{
    if(srvSendBuf == NULL || cliConn.recvCb == NULL) {
        NABTO_TEST_CHECK(false);
    } else {
        np_connection_received_callback cb = cliConn.recvCb;
        cliConn.recvCb = NULL;
        cb(NABTO_EC_OK, &cliConn, 0, srvSendBuf, srvSendBufSize, cliConn.recvData);
        srvSendBuf = NULL;
        srvConn.sentCb(NABTO_EC_OK, srvConn.sentData);
    }
}

/* ========= Conn impl ======== */
void conn_async_create(struct np_platform* pl, np_connection* conn, struct np_connection_channel* channel,
                         struct np_connection_id* id, np_connection_created_callback cb, void* data)
{
    
}

struct np_connection_id* conn_get_id(struct np_platform* pl, np_connection* conn)
{
    return &conn->id;
}

void conn_async_send_to(struct np_platform* pl, np_connection* conn, uint8_t channelId,
                          np_communication_buffer* buffer, uint16_t bufferSize,
                          np_connection_sent_callback cb, void* data)
{
    conn->sentCb = cb;
    conn->sentData = data;
    if (conn == &srvConn) {
        srvSendBuf = buffer;
        srvSendBufSize = bufferSize;
        np_event_queue_post(pl, &conn->ev, &test_async_send_to_client, conn);
    } else if (conn == &cliConn) {
        cliSendBuf = buffer;
        cliSendBufSize = bufferSize;
        np_event_queue_post(pl, &conn->ev, &test_async_send_to_server, conn);
    } else {
        NABTO_TEST_CHECK(false);
    }
}

void conn_async_recv_from(struct np_platform* pl, np_connection* conn,
                         np_connection_received_callback cb, void* data)
{
    conn->recvCb = cb;
    conn->recvData = data;
}

np_error_code conn_cancel_async_recv(struct np_platform* pl, np_connection* conn)
{
    conn->recvCb = NULL;
    return NABTO_EC_OK;
}

np_error_code conn_cancel_async_send(struct np_platform* pl, np_connection* conn)
{
    conn->sentCb = NULL;
    return NABTO_EC_OK;
}
/* ========= Conn impl end  ======== */


/* ========= Callbacks ========*/
bool cliConnCbCalled = false;
np_dtls_cli_context* cliCtx = NULL;
void test_dtls_cli_conn_cb(const np_error_code ec, np_dtls_cli_context* ctx, void* data)
{
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);
    cliConnCbCalled = true;
    cliCtx = ctx;
}

bool cliSendCbCalled = false;
void test_dtls_cli_send_to_callback(const np_error_code ec, void* data)
{
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);
    cliSendCbCalled = true;
}

const char srvSendTestBuf[] = {AT_DEVICE_LB, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90};
bool cliRecvCbCalled = false;
void test_dtls_cli_received_callback(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                                     np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    NABTO_TEST_CHECK(ec==NABTO_EC_OK);
    cliRecvCbCalled = true;
    NABTO_TEST_CHECK(memcmp(pl.buf.start(buffer), srvSendTestBuf, 10) == 0);
}

bool srvSendCbCalled = false;
void test_dtls_srv_send_to_callback(const np_error_code ec, void* data)
{
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);
    srvSendCbCalled = true;
}

const char cliSendTestBuf[] = {AT_DEVICE_LB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
bool srvRecvCbCalled = false;
void test_dtls_srv_received_callback(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                                     np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    NABTO_TEST_CHECK(ec==NABTO_EC_OK);
    srvRecvCbCalled = true;
    NABTO_TEST_CHECK(memcmp(pl.buf.start(buffer), cliSendTestBuf, 10) == 0);
}

/* ========= Callbacks end ==========*/

void test_dtls_connection()
{
    struct np_dtls_srv_connection* dtlsS;
    np_error_code ec;
    struct np_dtls_srv_send_context sendCtx;

    np_platform_init(&pl);
    nm_unix_comm_buf_init(&pl);
    np_ts_init(&pl);

    pl.conn.async_create = &conn_async_create;
    pl.conn.get_id = &conn_get_id;
    pl.conn.async_send_to = &conn_async_send_to;
    pl.conn.async_recv_from = &conn_async_recv_from;
    pl.conn.cancel_async_recv = &conn_cancel_async_recv;
    pl.conn.cancel_async_send = &conn_cancel_async_send;
    

    np_dtls_cli_init(&pl, devicePublicKey, strlen((const char*)devicePublicKey), devicePrivateKey, strlen((const char*)devicePrivateKey));
    np_dtls_srv_init(&pl, devicePublicKey, strlen((const char*)devicePublicKey), devicePrivateKey, strlen((const char*)devicePrivateKey));

    ec = pl.dtlsS.create(&pl, &srvConn, &dtlsS);
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);
    ec = pl.dtlsC.async_connect(&pl, &cliConn, &test_dtls_cli_conn_cb, NULL);
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);

    np_event_queue_execute_all(&pl);

    NABTO_TEST_CHECK(cliConnCbCalled);
    NABTO_TEST_CHECK(cliCtx != NULL);

    ec = pl.dtlsS.async_recv_from(&pl, dtlsS, &test_dtls_srv_received_callback, NULL);
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);
    ec = pl.dtlsC.async_send_to(&pl, cliCtx, 0xff, (uint8_t*) cliSendTestBuf, 10, &test_dtls_cli_send_to_callback, NULL);
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);

    np_event_queue_execute_all(&pl);

    NABTO_TEST_CHECK(srvRecvCbCalled);
    NABTO_TEST_CHECK(cliSendCbCalled);

    ec = pl.dtlsC.async_recv_from(&pl, cliCtx, AT_DEVICE_LB, &test_dtls_cli_received_callback, NULL);
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);
    sendCtx.buffer = (uint8_t*) srvSendTestBuf;
    sendCtx.bufferSize = 10;
    sendCtx.cb = &test_dtls_srv_send_to_callback;
    sendCtx.data = NULL;
    ec = pl.dtlsS.async_send_to(&pl, dtlsS, 0xff, &sendCtx);
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);

    np_event_queue_execute_all(&pl);
    NABTO_TEST_CHECK(cliRecvCbCalled);
    NABTO_TEST_CHECK(srvSendCbCalled);
}
