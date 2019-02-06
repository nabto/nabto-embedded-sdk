#include "nc_attacher.h"

#include <platform/np_logging.h>
#include <platform/np_platform.h>
#include <platform/np_unit_test.h>
#include <core/nc_tests.h>
#include <core/nc_packet.h>

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

const char* appVer = "0.0.1";
const char* appName = "Weather_app";
const char* hostname = "localhost";

struct np_communication_buffer {
    uint8_t buf[1500];
};

struct np_ip_address rec[1];

struct np_udp_socket* sock;

np_dtls_cli_context* crypCtx;

np_communication_buffer buf;
bool callbackReceived = false;
bool validAdReqSend = false;
bool validAnReqSend = false;
bool crypAdRecvCalled = false;
bool crypAnRecvCalled = false;
bool kaStarted = false;
uint32_t kaInt = 30000;
uint8_t kaReInt = 2;
uint8_t kaMaxRe = 15;
uint32_t sessionId = 0x42424242;
const char alpn[] = "n5";

/* state to know which packet attacher is to receive next: 
 * 0 NONE, 
 * 1 ATTACH_DISPATCH_RESPONSE,
 * 2 ATTACH_SERVER_HELLO
*/
int nc_attacher_test_recvState = 0;

// communication buffer impl
np_communication_buffer* nc_attacher_test_allocate() { return (np_communication_buffer*)malloc(sizeof(struct np_communication_buffer)); }
void nc_attacher_test_free(np_communication_buffer* buffer) {free(buffer);}
uint8_t* nc_attacher_test_start(np_communication_buffer* buffer) { return buffer->buf; }
uint16_t nc_attacher_test_size(np_communication_buffer* buffer) { return 1500; }

// dtls cli impl
np_error_code nc_attacher_test_cryp_send(struct np_platform* pl, np_dtls_cli_context* ctx, uint8_t channelId,
                                   uint8_t* buffer, uint16_t bufferSize, np_dtls_send_to_callback cb, void* data)
{
    if(buffer[0] == AT_DEVICE_LB) {
        if(buffer[1] == CT_DEVICE_LB_REQUEST) {
            uint16_t ext = (((uint16_t)buffer[2]) << 8) + buffer[3];
            // TODO: check all three extensions not just first
            if (ext == EX_NABTO_VERSION || ext == EX_APPLICATION_NAME || ext == EX_APPLICATION_VERSION) {
                validAdReqSend = true;
                nc_attacher_test_recvState = 1;
                cb(NABTO_EC_OK, data);
                return NABTO_EC_OK;
            }
        }
        
    } else if(buffer[0] == AT_DEVICE_RELAY) {
        if(buffer[1] == CT_DEVICE_RELAY_HELLO_REQUEST) {
            // TODO: check all extentions not just first 
            uint16_t ext = (((uint16_t)buffer[2]) << 8) + buffer[3];
            if (ext == EX_NABTO_VERSION || ext == EX_APPLICATION_NAME || ext == EX_APPLICATION_VERSION || ext == EX_APPLICATION_VERSION || ext == EX_SESSION_ID || ext == EX_ATTACH_INDEX) {
                validAnReqSend = true;
                nc_attacher_test_recvState = 2;
                cb(NABTO_EC_OK, data);
                return NABTO_EC_OK;
            }
        }
    } else {
        nc_attacher_test_recvState = 0;
        cb(NABTO_EC_FAILED, data);
    }
    return NABTO_EC_OK;
}
np_error_code nc_attacher_test_cryp_recv(struct np_platform* pl, np_dtls_cli_context* ctx,
                                     enum application_data_type type, np_dtls_received_callback cb, void* data)
{
    np_communication_buffer resp;
    uint8_t *ptr = resp.buf+2;
    if (nc_attacher_test_recvState == 1) {
        resp.buf[0] = AT_DEVICE_LB;
        resp.buf[1] = CT_DEVICE_LB_RESPONSE;
        ptr = uint16_write_forward(ptr, EX_DTLS_EP); 
        ptr = uint16_write_forward(ptr, 31); //extension data length
        ptr = uint16_write_forward(ptr, 0x4242); // port
        *ptr = 3; ptr++; // az
        memcpy(ptr, "1234567890123456", 16); // fp
        ptr += 16;
        ptr = uint16_write_forward(ptr, 10); // dns length
        memcpy(ptr, "localhost", 10); // host
        ptr += 10;
        ptr = uint16_write_forward(ptr, EX_SESSION_ID);
        ptr = uint16_write_forward(ptr, 4); // extension data length
        ptr = uint32_write_forward(ptr, sessionId); // session ID
        
        nc_attacher_test_recvState = 0;
        cb(NABTO_EC_OK, 0, 0, &resp, 45, data);
        crypAdRecvCalled = true;
    } else if (nc_attacher_test_recvState == 2) {
        // 02 02 00 05 00 06 00 00 75 30 02 0f 
        ptr = resp.buf;
        *ptr = AT_DEVICE_RELAY;
        ptr++;
        *ptr = CT_DEVICE_RELAY_HELLO_RESPONSE;
        ptr++;
        ptr = uint16_write_forward(ptr, EX_KEEP_ALIVE_SETTINGS);
        ptr = uint16_write_forward(ptr, 6);
        ptr = uint32_write_forward(ptr, kaInt);
        *ptr = kaReInt; ptr++;
        *ptr = kaMaxRe; ptr++;
        nc_attacher_test_recvState = 0;
        cb(NABTO_EC_OK, 0, 0, &resp, 12, data);
        crypAnRecvCalled = true;
    } else {
        //cb(NABTO_EC_FAILED, 0, 0, NULL, 0, data);
        nc_attacher_test_recvState = 0;
    }
    return NABTO_EC_OK;
}
np_error_code nc_attacher_test_cryp_conn(struct np_platform* pl, struct nc_udp_dispatch_context* conn,
                                         np_udp_endpoint ep,
                                         np_dtls_cli_connect_callback cb, void* data)
{
    cb(NABTO_EC_OK, crypCtx, data);
    return NABTO_EC_OK;
}
np_error_code nc_attacher_test_cryp_close(struct np_platform* pl, np_dtls_cli_context* ctx,
                                          np_dtls_close_callback cb, void* data)
{
    cb(NABTO_EC_OK, data);
    return NABTO_EC_OK;
}
np_error_code nc_attacher_test_cryp_cancel(struct np_platform* pl, np_dtls_cli_context* ctx,
                                      enum application_data_type type)
{
    return NABTO_EC_OK;
}

np_error_code nc_attacher_test_cryp_get_fingerprint(struct np_platform* pl, np_dtls_cli_context* ctx, uint8_t* fp)
{
    memcpy(fp, "1234567890123456", 16); // fp
    return NABTO_EC_OK;
}

const char* nc_attacher_test_cryp_get_alpn_protocol(np_dtls_cli_context* ctx)
{
    return alpn;
}

np_error_code nc_attacher_test_start_keep_alive(np_dtls_cli_context* ctx, uint32_t interval,
                                      uint8_t retryInterval, uint8_t maxRetries)
{
    if (interval == kaInt && retryInterval == kaReInt && maxRetries == kaMaxRe) {
        kaStarted = true;
        return NABTO_EC_OK;
    }
    return NABTO_EC_FAILED;
}

// dns impl
np_error_code nc_attacher_test_dns(struct np_platform* pl, const char* host, np_dns_resolve_callback cb, void* data)
{
    cb(NABTO_EC_OK, rec, 1, data);
    return NABTO_EC_OK;
}

// udp impl
void nc_attacher_test_udp_create(np_udp_socket_created_callback cb, void* data)
{
    cb(NABTO_EC_OK, sock, data);
}

void nc_attacher_test_udp_async_recv_from(np_udp_socket* sock, np_udp_packet_received_callback cb, void* data)
{

}

// ts impl
void nc_attacher_test_ts_set(np_timestamp* ev, uint32_t ms) {}

// final attach callback
void nc_attacher_test_callback(const np_error_code ec, void* data)
{
    if (ec == NABTO_EC_OK) {
        callbackReceived = true;
    }
}


void nc_attacher_test_attach()
{
    struct nc_attach_context attach;
    struct np_platform pl;
//    np_log_init(&pl);
    np_platform_init(&pl);
    pl.dtlsC.async_connect = &nc_attacher_test_cryp_conn;
    pl.dtlsC.async_send_to = &nc_attacher_test_cryp_send;
    pl.dtlsC.async_recv_from = &nc_attacher_test_cryp_recv;
    pl.dtlsC.async_close = &nc_attacher_test_cryp_close;
    pl.dtlsC.cancel_recv_from = &nc_attacher_test_cryp_cancel;
    pl.dtlsC.get_fingerprint = & nc_attacher_test_cryp_get_fingerprint;
    pl.dtlsC.get_alpn_protocol = & nc_attacher_test_cryp_get_alpn_protocol;
    pl.dtlsC.start_keep_alive = &nc_attacher_test_start_keep_alive;
    
    pl.buf.start = &nc_attacher_test_start;
    pl.buf.allocate = &nc_attacher_test_allocate;
    pl.buf.free = &nc_attacher_test_free;
    pl.buf.size = &nc_attacher_test_size;

    pl.dns.async_resolve = &nc_attacher_test_dns;

    pl.udp.async_create = &nc_attacher_test_udp_create;
    pl.udp.async_recv_from = &nc_attacher_test_udp_async_recv_from;

    pl.ts.set_future_timestamp = &nc_attacher_test_ts_set;

//    np_dtls_cli_context* crypCtx;
    callbackReceived = false;
    memset(rec[0].v6.addr, 0, 16);
    rec[0].v6.addr[15] = 1; // ::1
    
    struct nc_attach_parameters attachParams;

    attachParams.appName = appName;
    attachParams.appVersion = appVer;
    attachParams.hostname = hostname;

    
    nc_attacher_async_attach(&attach, &pl, &attachParams, &nc_attacher_test_callback, NULL);
    
    NABTO_TEST_CHECK(callbackReceived);
    NABTO_TEST_CHECK(crypAdRecvCalled);
    NABTO_TEST_CHECK(crypAnRecvCalled);
    NABTO_TEST_CHECK(validAdReqSend);
    NABTO_TEST_CHECK(validAnReqSend);
}

void nc_attacher_tests()
{
    nc_attacher_test_attach();
}
