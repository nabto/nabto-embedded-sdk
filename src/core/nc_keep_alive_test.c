#include "nc_keep_alive.h"

#include <platform/np_logging.h>
#include <platform/np_event_queue.h>
#include <platform/np_platform.h>
#include <platform/np_unit_test.h>
#include <core/nc_tests.h>
#include <core/nc_packet.h>
#include <stdlib.h>
#include <string.h>


uint8_t testBuffer[30];
uint32_t nc_keep_alive_test_recvCount = 0;
uint32_t nc_keep_alive_test_sentCount = 0;
np_dtls_cli_received_callback nc_keep_alive_test_cryp_recvCb;
void* nc_keep_alive_test_cryp_recvCbData;
bool validKaReqSend = false;
bool crypKArecv1Called = false;
bool nc_keep_alive_test_cd_success = false;
uint8_t nc_keep_alive_test_recvState = 0;
np_dtls_cli_context* crypCtx;


// communication buffer impl
struct np_communication_buffer {
    uint8_t buf[1500];
};
np_communication_buffer* nc_keep_alive_test_allocate() { return (np_communication_buffer*)malloc(sizeof(struct np_communication_buffer)); }
void nc_keep_alive_test_free(np_communication_buffer* buffer) {free(buffer);}
uint8_t* nc_keep_alive_test_start(np_communication_buffer* buffer) { return buffer->buf; }
uint16_t nc_keep_alive_test_size(np_communication_buffer* buffer) { return 1500; }

// timesamp impl
np_timestamp time = 0;
bool nc_keep_alive_test_ts_passed_or_now(np_timestamp* timestamp)
{
    return (time >= *timestamp);
}

void nc_keep_alive_test_ts_now(np_timestamp* ts)
{
    *ts = time;
}
bool nc_keep_alive_test_ts_less_or_equal(np_timestamp* t1, np_timestamp* t2)
{
    return (*t1 <= *t2);
}

void nc_keep_alive_test_ts_set_future_timestamp(np_timestamp* ts, uint32_t milliseconds)
{
    *ts = time + milliseconds;
}

// dtls cli impl
np_error_code nc_keep_alive_test_cryp_send(struct np_platform* pl, np_dtls_cli_context* ctx, uint8_t channelId,
                                   uint8_t* buffer, uint16_t bufferSize, np_dtls_cli_send_to_callback cb, void* data)
{
    np_communication_buffer resp;
    if(buffer[0] == AT_KEEP_ALIVE) {
        if(buffer[1] == CT_KEEP_ALIVE_REQUEST) {
            if (bufferSize == 18) {
                memcpy(testBuffer, buffer, bufferSize);
                validKaReqSend = true;
                nc_keep_alive_test_recvState = 1;
                nc_keep_alive_test_sentCount++;
                cb(NABTO_EC_OK, data);
                
                memcpy(resp.buf, testBuffer, 18);
                resp.buf[1] = CT_KEEP_ALIVE_RESPONSE;
                nc_keep_alive_test_recvCount++;
                nc_keep_alive_test_cryp_recvCb(NABTO_EC_OK, 0, 0, &resp, 18, nc_keep_alive_test_cryp_recvCbData);
                return NABTO_EC_OK;
            }
        }
        
    } else {
        nc_keep_alive_test_recvState = 0;
        cb(NABTO_EC_FAILED, data);
    }
    return NABTO_EC_OK;
}
np_error_code nc_keep_alive_test_cryp_recv(struct np_platform* pl, np_dtls_cli_context* ctx,
                                     enum application_data_type type, np_dtls_cli_received_callback cb, void* data)
{
    nc_keep_alive_test_cryp_recvCb = cb;
    nc_keep_alive_test_cryp_recvCbData = data;
    crypKArecv1Called = true;
    return NABTO_EC_OK;
}
np_error_code nc_keep_alive_test_cryp_conn(struct np_platform* pl, np_connection* conn,
                                         np_dtls_cli_connect_callback cb, void* data)
{
    cb(NABTO_EC_OK, crypCtx, data);
    return NABTO_EC_OK;
}
np_error_code nc_keep_alive_test_cryp_close(struct np_platform* pl, np_dtls_cli_context* ctx,
                                          np_dtls_cli_close_callback cb, void* data)
{
    cb(NABTO_EC_OK, data);
    return NABTO_EC_OK;
}
np_error_code nc_keep_alive_test_cryp_cancel(struct np_platform* pl, np_dtls_cli_context* ctx,
                                      enum application_data_type type)
{
    return NABTO_EC_OK;
}

np_error_code nc_keep_alive_test_cryp_get_packet_count(np_dtls_cli_context* ctx,
                                                       uint32_t* recvCount, uint32_t* sentCount)
{
    *recvCount = nc_keep_alive_test_recvCount;
    *sentCount = nc_keep_alive_test_sentCount;
    return NABTO_EC_OK;
}

void nc_keep_alive_test_cb(const np_error_code ec, void* data) {
    if (ec == NABTO_EC_OK && *((int*)data) == 42) {
        nc_keep_alive_test_cd_success = true;
    }
}

void nc_keep_alive_test_ka()
{
    struct np_platform pl;
    np_platform_init(&pl);
    pl.dtlsC.async_connect = &nc_keep_alive_test_cryp_conn;
    pl.dtlsC.async_send_to = &nc_keep_alive_test_cryp_send;
    pl.dtlsC.async_recv_from = &nc_keep_alive_test_cryp_recv;
    pl.dtlsC.async_close = &nc_keep_alive_test_cryp_close;
    pl.dtlsC.cancel_recv_from = &nc_keep_alive_test_cryp_cancel;
    pl.dtlsC.get_packet_count = &nc_keep_alive_test_cryp_get_packet_count;

    pl.buf.start = &nc_keep_alive_test_start;
    pl.buf.allocate = &nc_keep_alive_test_allocate;
    pl.buf.free = &nc_keep_alive_test_free;
    pl.buf.size = &nc_keep_alive_test_size;

    time = 0;
    pl.ts.passed_or_now = &nc_keep_alive_test_ts_passed_or_now;
    pl.ts.less_or_equal = &nc_keep_alive_test_ts_less_or_equal;
    pl.ts.now = &nc_keep_alive_test_ts_now;
    pl.ts.set_future_timestamp = &nc_keep_alive_test_ts_set_future_timestamp;

    int testData = 42;
    struct nc_keep_alive_context ctx;
    nc_keep_alive_init_cli(&pl, &ctx, crypCtx, &nc_keep_alive_test_cb, &testData);
    np_event_queue_execute_all(&pl);

    for (int i = 0; i < 16; i++) {
        NABTO_TEST_CHECK(crypKArecv1Called);
        NABTO_TEST_CHECK(!validKaReqSend);
        time = time + 2000;
        np_event_queue_execute_all(&pl);
    }

    time = time + 1000;
    np_event_queue_execute_all(&pl);
    NABTO_TEST_CHECK(crypKArecv1Called);
    NABTO_TEST_CHECK(validKaReqSend);

    for (int i = 0; i < 16; i++) {
        time = time + 2000;
        np_event_queue_execute_all(&pl);
    }

    validKaReqSend = false;
    nc_keep_alive_test_recvCount = 2;
    nc_keep_alive_test_sentCount = 2;
    np_event_queue_execute_all(&pl);
    NABTO_TEST_CHECK(crypKArecv1Called);
    NABTO_TEST_CHECK(!validKaReqSend);
    
}

void nc_keep_alive_tests() {
    nc_keep_alive_test_ka();
}
