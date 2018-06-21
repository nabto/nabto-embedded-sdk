#include "nc_connection.h"

#include <platform/np_logging.h>
#include <platform/np_platform.h>
#include <platform/np_unit_test.h>
#include <platform/np_event_queue.h>

#include <core/nc_tests.h>
#include <core/nc_packet.h>

#include <string.h>
#include <stdlib.h>

struct np_communication_buffer {
    uint8_t buf[1500];
};

bool connCreated = false;
bool connSent = false;
bool udpSendCalled = false;
bool udpSendFailed = false;
bool recvFromStun = false;
bool recvFromDtls = false;
int nRecvCb = 0;

// communication buffer impl
np_communication_buffer* nc_connection_test_allocate() { return (np_communication_buffer*)malloc(sizeof(struct np_communication_buffer)); }
void nc_connection_test_free(np_communication_buffer* buffer) {free(buffer);}
uint8_t* nc_connection_test_start(np_communication_buffer* buffer) { return buffer->buf; }
uint16_t nc_connection_test_size(np_communication_buffer* buffer) { return 1500; }

// udp impl
/*
void nc_connection_test_udp_create(np_udp_socket_created_callback cb, void* data)
{
    cb(NABTO_EC_OK, sock, data);
}*/
void nc_connection_test_udp_send(np_udp_socket* socket, struct np_udp_endpoint* ep, np_communication_buffer* buffer, uint16_t bufferSize, np_udp_packet_sent_callback cb, void* data)
{
    if(ep->port == 42424 && ep->ip.v4.addr[0] == 128 && ep->ip.v4.addr[1] == 129 && ep->ip.v4.addr[2] == 130 && ep->ip.v4.addr[3] == 131 && bufferSize == 16) {
        udpSendCalled = true;
        cb(NABTO_EC_OK, data);
    } else {
        NABTO_LOG_INFO(0, "ep port: %u, ep ip0: %u, ep ip1: %u, ep ip2: %u, ep ip3: %u, bufferSize: %u", ep->port, ep->ip.v4.addr[0], ep->ip.v4.addr[1], ep->ip.v4.addr[2], ep->ip.v4.addr[3], bufferSize);
        udpSendFailed = true;
        cb(NABTO_EC_FAILED, data);
    }
    
}
void nc_connection_test_udp_recv(np_udp_socket* socket, enum np_channel_type type, np_udp_packet_received_callback cb, void* data)
{
    np_communication_buffer buf;
    if (type == NABTO_CHANNEL_STUN) {
        recvFromStun = true;
    } else if (type == NABTO_CHANNEL_DTLS) {
        recvFromDtls = true;
    }
    struct np_udp_endpoint ep;
    cb(NABTO_EC_OK, ep , &buf, 0, data);
}

// test impl
void nc_connection_test_recv_cb(const np_error_code ec, struct np_connection* conn,
                                uint8_t channelId, np_communication_buffer* buffer,
                                uint16_t bufferSize, void* data)
{
    if (ec == NABTO_EC_OK) {
        nRecvCb++;
    }
}
void nc_connection_test_send_cb(const np_error_code ec, void* data)
{
    if (ec == NABTO_EC_OK) {
        connSent = true;
    }
}

void nc_connection_test_created_cb(const np_error_code ec, uint8_t channelId, void* data)
{
    if(ec == NABTO_EC_OK && channelId == 42) {
        connCreated = true;
    }
}

void nc_connection_test_send_to_channel()
{
    struct np_platform pl;
    np_connection conn;
    struct np_connection_channel chan;
    struct np_connection_channel chan2;
    struct np_connection_id id;
    uint8_t idArr[] = {240, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 42};
    np_communication_buffer commbuf;
    struct np_udp_socket* sock = (struct np_udp_socket*)&id; // size of sock is not know, and the pointer must not point to NULL, so using arbitrary memory address
    np_error_code ec;
    
    np_platform_init(&pl);
    // pl.udp.async_create = &nc_connection_test_udp_create;
    pl.udp.async_send_to = &nc_connection_test_udp_send;
    pl.udp.async_recv_from = &nc_connection_test_udp_recv;
    
    pl.buf.start = &nc_connection_test_start;
    pl.buf.allocate = &nc_connection_test_allocate;
    pl.buf.free = &nc_connection_test_free;
    pl.buf.size = &nc_connection_test_size;

    chan.type = NABTO_CHANNEL_DTLS;
    chan.sock = sock;
    chan.channelId = 42;

    chan2.type = NABTO_CHANNEL_STUN;
    chan2.sock = sock;
    chan2.channelId = 0x42;
    chan2.ep.port = 42424;
    chan2.ep.ip.v4.addr[0] = 128;
    chan2.ep.ip.v4.addr[1] = 129;
    chan2.ep.ip.v4.addr[2] = 130;
    chan2.ep.ip.v4.addr[3] = 131;

    memcpy(id.id, idArr, 16);

    memcpy(commbuf.buf, idArr, 16); // using data we already have to send
    
    nc_connection_async_create(&pl, &conn, &chan, &id, &nc_connection_test_created_cb, NULL);
    np_event_queue_poll_one(&pl);
    
    NABTO_TEST_CHECK(connCreated);
    
    ec = nc_connection_add_channel(&pl, &conn, &chan2);
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);

    ec = nc_connection_rem_channel(&pl, &conn, chan.channelId);
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);

    nc_connection_async_send_to(&pl, &conn, chan2.channelId, &commbuf, 16, &nc_connection_test_send_cb, NULL);

    NABTO_TEST_CHECK(udpSendCalled);
    NABTO_TEST_CHECK(!udpSendFailed);
    NABTO_TEST_CHECK(connSent);

    nc_connection_async_recv_from(&pl, &conn, &nc_connection_test_recv_cb, NULL);

    NABTO_TEST_CHECK(recvFromStun);
    NABTO_TEST_CHECK(!recvFromDtls);
    NABTO_TEST_CHECK(nRecvCb == 1);
}

void nc_connection_tests()
{
    nc_connection_test_send_to_channel();
}
