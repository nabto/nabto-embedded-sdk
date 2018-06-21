#include "nc_attacher.h"

#include <platform/np_logging.h>
#include <platform/np_platform.h>
#include <platform/np_unit_test.h>
#include <core/nc_tests.h>
#include <core/nc_packet.h>

#include <string.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdlib.h>

struct np_communication_buffer {
    uint8_t buf[1500];
};

struct np_ip_address rec[1];

struct np_udp_socket* sock;

np_crypto_context* crypCtx;

np_communication_buffer buf;
bool callbackReceived = false;
bool validAdReqSend = false;
bool validAnReqSend = false;
bool crypAdRecvCalled = false;
bool crypAnRecvCalled = false;

/* state to know which packet attacher is to receive next: 
 * 0 NONE, 
 * 1 ATTACH_DISPATCH_RESPONSE,
 * 2 ATTACH_SERVER_HELLO
*/
int recvState = 0; 

// communication buffer impl
np_communication_buffer* nc_attacher_test_allocate() { return (np_communication_buffer*)malloc(sizeof(struct np_communication_buffer)); }
void nc_attacher_test_free(np_communication_buffer* buffer) {free(buffer);}
uint8_t* nc_attacher_test_start(np_communication_buffer* buffer) { return buffer->buf; }
uint16_t nc_attacher_test_size(np_communication_buffer* buffer) { return 1500; }

// crypto impl
np_error_code nc_attacher_test_cryp_send(struct np_platform* pl, np_crypto_context* ctx, uint8_t channelId,
                                   uint8_t* buffer, uint16_t bufferSize, np_crypto_send_to_callback cb, void* data)
{
    if(buffer[0] == ATTACH_DISPATCH) {
        if(buffer[1] == ATTACH_DISPATCH_REQUEST) {
            uint16_t ext = (((uint16_t)buffer[4]) << 8) + buffer[5];
            if (ext == UDP_IPV4_EP || ext == UDP_IPV6_EP) {
                validAdReqSend = true;
                recvState = 1;
                cb(NABTO_EC_OK, data);
            }
        }
    } else if(buffer[0] == ATTACH) {
        if(buffer[1] == ATTACH_DEVICE_HELLO) {
            uint16_t ext = (((uint16_t)buffer[4]) << 8) + buffer[5];
            if (ext == UDP_IPV4_EP || ext == UDP_IPV6_EP) {
                uint16_t endOfExt = NABTO_PACKET_HEADER_SIZE+(((uint16_t)buffer[2]) << 8)+buffer[3]+2;
                if(((((uint16_t)buffer[endOfExt]) << 8 ) + buffer[endOfExt+1] ) == 666) { // token
                    validAnReqSend = true;
                    recvState = 2;
                    cb(NABTO_EC_OK, data);
                    return NABTO_EC_OK;
                }
            }
        }
    } else {
        recvState = 0;
        cb(NABTO_EC_FAILED, data);
    }
    return NABTO_EC_OK;
}
np_error_code nc_attacher_test_cryp_recv(struct np_platform* pl, np_crypto_context* ctx,
                                     enum application_data_type type, np_crypto_received_callback cb, void* data)
{
    np_communication_buffer resp;
    uint8_t *ptr = resp.buf;
    if (recvState == 1) {
        resp.buf[0] = ATTACH_DISPATCH;
        resp.buf[1] = ATTACH_DISPATCH_RESPONSE;
        ptr = uint16_write_forward(ptr+2, 18); // extensions length
        ptr = uint16_write_forward(ptr, UDP_DNS_EP); 
        ptr = uint16_write_forward(ptr, 14); //extension data length
        ptr = uint16_write_forward(ptr, 4242); // port
        ptr = uint16_write_forward(ptr, 10); // string length
        memcpy(ptr, "localhost", 10); // host
        ptr += 10;
        ptr = uint16_write_forward(ptr, 2); // token length
        ptr = uint16_write_forward(ptr, 666); // random token data
        
        recvState = 0;
        cb(NABTO_EC_OK, 0, 0, &resp, 26, data);
        crypAdRecvCalled = true;
    } else if (recvState == 2) {
        resp.buf[0] = ATTACH;
        resp.buf[1] = ATTACH_SERVER_HELLO;
        resp.buf[2] = 0;
        resp.buf[3] = 0;
        recvState = 0;
        cb(NABTO_EC_OK, 0, 0, &resp, 4, data);
        crypAnRecvCalled = true;
    } else {
        //cb(NABTO_EC_FAILED, 0, 0, NULL, 0, data);
        recvState = 0;
    }
    return NABTO_EC_OK;
}
np_error_code nc_attacher_test_cryp_conn(struct np_platform* pl, np_connection* conn,
                                   np_crypto_connect_callback cb, void* data)
{
    cb(NABTO_EC_OK, crypCtx, data);
    return NABTO_EC_OK;
}
np_error_code nc_attacher_test_cryp_close(struct np_platform* pl, np_crypto_context* ctx,
                                 np_crypto_close_callback cb, void* data)
{
    cb(NABTO_EC_OK, data);
    return NABTO_EC_OK;
}
np_error_code nc_attacher_test_cryp_cancel(struct np_platform* pl, np_crypto_context* ctx,
                                      enum application_data_type type)
{
    return NABTO_EC_OK;
}

// dns impl
np_error_code nc_attacher_test_dns(struct np_platform* pl, const char* host, np_dns_resolve_callback cb, void* data)
{
    cb(NABTO_EC_OK, rec, 1, data);
}

// udp impl
void nc_attacher_test_udp_create(np_udp_socket_created_callback cb, void* data)
{
    cb(NABTO_EC_OK, sock, data);
}

// connection impl
void nc_attacher_test_conn_create(struct np_platform* pl, np_connection* conn,
                                  struct np_connection_channel* channel, struct np_connection_id* id,
                                  np_connection_created_callback cb, void* data)
{
    cb(NABTO_EC_OK, 0, data);
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
    struct np_platform pl;
    np_platform_init(&pl);
    pl.cryp.async_connect = &nc_attacher_test_cryp_conn;
    pl.cryp.async_send_to = &nc_attacher_test_cryp_send;
    pl.cryp.async_recv_from = &nc_attacher_test_cryp_recv;
    pl.cryp.async_close = &nc_attacher_test_cryp_close;
    pl.cryp.cancel_recv_from = &nc_attacher_test_cryp_cancel;

    pl.buf.start = &nc_attacher_test_start;
    pl.buf.allocate = &nc_attacher_test_allocate;
    pl.buf.free = &nc_attacher_test_free;
    pl.buf.size = &nc_attacher_test_size;

    pl.dns.async_resolve = &nc_attacher_test_dns;

    pl.udp.async_create = &nc_attacher_test_udp_create;

    pl.conn.async_create = &nc_attacher_test_conn_create;

    pl.ts.set_future_timestamp = &nc_attacher_test_ts_set;

    np_crypto_context* crypCtx;
    callbackReceived = false;
    inet_pton(AF_INET6, "::1", rec[0].v6.addr);
    
    nc_attacher_async_attach(&pl, &nc_attacher_test_callback, NULL);
    
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
