#include "nc_client_connect.h"

#include <platform/np_logging.h>
#include <platform/np_dtls_srv.h>
#include <platform/np_platform.h>
#include <platform/np_unit_test.h>
#include <core/nc_tests.h>
#include <core/nc_packet.h>

#include <string.h>
#include <stdlib.h>

int nc_client_connect_test_recvState = 0; 

struct np_dtls_srv_connection* crypCtx;
struct np_udp_socket* sock;
struct np_platform pl;
char testCtx[] = "TestData";
struct np_connection_id id;

void nc_client_connect_test_recv_from_clientConn(const np_error_code ec, struct np_udp_endpoint ep,
                                                 np_communication_buffer* buffer, uint16_t bufferSize, void* data);

// communication buffer impl
struct np_communication_buffer {
    uint8_t buf[1500];
};
np_communication_buffer* nc_client_connect_test_allocate() { return (np_communication_buffer*)malloc(sizeof(struct np_communication_buffer)); }
void nc_client_connect_test_free(np_communication_buffer* buffer) {free(buffer);}
uint8_t* nc_client_connect_test_start(np_communication_buffer* buffer) { return buffer->buf; }
uint16_t nc_client_connect_test_size(np_communication_buffer* buffer) { return 1500; }

// dtls srv impl
np_error_code nc_client_connect_test_cryp_send(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                               uint8_t channelId, uint8_t* buffer, uint16_t bufferSize,
                                               np_dtls_send_to_callback cb, void* data)
{

/*    if(buffer[0] == AT_DEVICE_LB) {
        if(buffer[1] == CT_DEVICE_LB_REQUEST) {
            uint16_t ext = (((uint16_t)buffer[2]) << 8) + buffer[3];
            // TODO: check all three extensions not just first
            if (ext == EX_NABTO_VERSION || ext == EX_APPLICATION_NAME || EX_APPLICATION_VERSION) {
                validAdReqSend = true;
                nc_client_connect_test_recvState = 1;
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
                nc_client_connect_test_recvState = 2;
                cb(NABTO_EC_OK, data);
                return NABTO_EC_OK;
            }
        }
    } else {
        nc_client_connect_test_recvState = 0;
        cb(NABTO_EC_FAILED, data);
    }
*/
    return NABTO_EC_OK;
}
np_error_code nc_client_connect_test_cryp_recv(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                               enum application_data_type type, np_dtls_received_callback cb, void* data)
{
    np_communication_buffer resp;
    uint8_t *ptr = resp.buf+2;
    if (nc_client_connect_test_recvState == 1) {
/*        resp.buf[0] = AT_DEVICE_LB;
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
        
        nc_client_connect_test_recvState = 0;
        cb(NABTO_EC_OK, 0, 0, &resp, 45, data);
        crypAdRecvCalled = true;
    } else if (nc_client_connect_test_recvState == 2) {
        resp.buf[0] = AT_DEVICE_RELAY;
        resp.buf[1] = CT_DEVICE_RELAY_HELLO_RESPONSE;
        resp.buf[2] = 0;
        resp.buf[3] = 0;
        nc_client_connect_test_recvState = 0;
        cb(NABTO_EC_OK, 0, 0, &resp, 4, data);
        crypAnRecvCalled = true;
*/
    } else {
        //cb(NABTO_EC_FAILED, 0, 0, NULL, 0, data);
        nc_client_connect_test_recvState = 0;
    }
    return NABTO_EC_OK;
}
np_error_code nc_client_connect_test_cryp_create(struct np_platform* pll, np_connection* conn,
                                                 struct np_dtls_srv_connection** ctx)
{
    pl.clientConn.async_recv_from(conn, &nc_client_connect_test_recv_from_clientConn, &testCtx);
    //cb(NABTO_EC_OK, crypCtx, data);
    return NABTO_EC_OK;
}
np_error_code nc_client_connect_test_cryp_close(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                                np_dtls_close_callback cb, void* data)
{
    cb(NABTO_EC_OK, data);
    return NABTO_EC_OK;
}
np_error_code nc_client_connect_test_cryp_cancel(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                                 enum application_data_type type)
{
    return NABTO_EC_OK;
}

// udp impl
void nc_client_connect_test_udp_create(np_udp_socket_created_callback cb, void* data)
{
    cb(NABTO_EC_OK, sock, data);
}

// connection impl
void nc_client_connect_test_conn_create(struct np_platform* pl, np_connection* conn,
                                  struct np_connection_channel* channel, struct np_connection_id* id,
                                  np_connection_created_callback cb, void* data)
{
    cb(NABTO_EC_OK, 0, data);
}

struct np_connection_id* nc_client_connect_test_conn_get_id(struct np_platform* pl, np_connection* conn) {
    return &id;
}

bool testRecvFromCalled = false;
// Test impl
void nc_client_connect_test_recv_from_clientConn(const np_error_code ec, struct np_udp_endpoint ep,
                                                 np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    uint8_t* ptr = pl.buf.start(buffer);
    NABTO_TEST_CHECK(*ptr == 240);
    NABTO_TEST_CHECK(memcmp(ptr+1, "12345678912345\0TEST_DATA" , 24) == 0);
    testRecvFromCalled = true;
}

void nc_client_connect_test_connect()
{
    struct np_udp_endpoint ep;
    np_communication_buffer* buf;
    uint8_t* ptr;
    uint8_t fp[16];
    memset(fp, 0, 16);
    
    id.id[0] = 240;
    memcpy(id.id+1, "12345678912345\0",14);
    np_platform_init(&pl);
    pl.dtlsS.create = &nc_client_connect_test_cryp_create;
    pl.dtlsS.async_send_to = &nc_client_connect_test_cryp_send;
    pl.dtlsS.async_recv_from = &nc_client_connect_test_cryp_recv;
    pl.dtlsS.async_close = &nc_client_connect_test_cryp_close;
    pl.dtlsS.cancel_recv_from = &nc_client_connect_test_cryp_cancel;

    pl.buf.start = &nc_client_connect_test_start;
    pl.buf.allocate = &nc_client_connect_test_allocate;
    pl.buf.free = &nc_client_connect_test_free;
    pl.buf.size = &nc_client_connect_test_size;

    pl.udp.async_create = &nc_client_connect_test_udp_create;

    pl.conn.async_create = &nc_client_connect_test_conn_create;
    pl.conn.get_id = &nc_client_connect_test_conn_get_id;

    nc_client_connect_init(&pl, fp);

    buf = pl.buf.allocate();
    ptr = pl.buf.start(buf);
    memcpy(ptr, id.id, 16);
    ptr += 16;
    memcpy(ptr, "TEST_DATA", 10);
    ptr += 10;
    pl.clientConn.recv(&pl, NABTO_EC_OK, sock, ep, buf, 26);
    
    NABTO_TEST_CHECK(testRecvFromCalled);
}

void nc_client_connect_tests()
{
    nc_client_connect_test_connect();
}
