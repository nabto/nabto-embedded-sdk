#include "nc_packet.h"

#include <platform/np_unit_test.h>
#include <core/nc_tests.h>

#include <stdlib.h>

struct np_communication_buffer {
    uint8_t buf[1500];
};

// communication buffer impl
np_communication_buffer* nc_packet_test_allocate() { return (np_communication_buffer*)malloc(sizeof(struct np_communication_buffer)); }
void nc_packet_test_free(np_communication_buffer* buffer) {free(buffer);}
uint8_t* nc_packet_test_start(np_communication_buffer* buffer) { return buffer->buf; }
uint16_t nc_packet_test_size(np_communication_buffer* buffer) { return 1500; }


void nc_packet_test_uint16_write_forward()
{
    uint8_t buffer[10];
    uint8_t* ptr = buffer;
    ptr = uint16_write_forward(buffer, 4242);
    NABTO_TEST_CHECK(buffer[0] = ((uint8_t)(4242 >> 8)));
    NABTO_TEST_CHECK(buffer[1] = ((uint8_t)4242));
    NABTO_TEST_CHECK(ptr == &buffer[2]);
}

void nc_packet_test_uint16_read_write()
{
    uint8_t buffer[10];
    uint16_t val = 4242;
    uint16_write(buffer, val);
    NABTO_TEST_CHECK(buffer[0] = ((uint8_t)(4242 >> 8)));
    NABTO_TEST_CHECK(buffer[1] = ((uint8_t)4242));
    NABTO_TEST_CHECK(uint16_read(buffer) == val);
}
void nc_packet_test_init_packet_header()
{
    uint8_t buffer[10];
    uint8_t* ptr = init_packet_header(buffer, AT_DEVICE_RELAY);
    NABTO_TEST_CHECK(buffer[0] == AT_DEVICE_RELAY);
    NABTO_TEST_CHECK(buffer[1] == 0);
    NABTO_TEST_CHECK(ptr = buffer + NABTO_PACKET_HEADER_SIZE);
}
void nc_packet_test_insert_packet_ext()
{
    struct np_platform pl;
    np_communication_buffer* buf;
    uint8_t* ptr;
    uint8_t* start;
    uint8_t data[] = {23, 34, 45, 56, 67, 78, 89};
    np_platform_init(&pl);
    pl.buf.allocate = &nc_packet_test_allocate;
    pl.buf.start = &nc_packet_test_start;
    pl.buf.size = &nc_packet_test_size;
    pl.buf.free = &nc_packet_test_free;
    buf = pl.buf.allocate();
    start = pl.buf.start(buf);
    ptr = init_packet_header(start, AT_DEVICE_RELAY);
    ptr = insert_packet_extension(&pl, ptr, EX_UDP_DNS_EP, data, 7);
    NABTO_TEST_CHECK(uint16_read(start+2) == EX_UDP_DNS_EP);
    NABTO_TEST_CHECK(uint16_read(start+4) == 7);
    NABTO_TEST_CHECK(*(start+6) == data[0]);
}
void nc_packet_test_write_length_data()
{
    uint8_t buffer[10];
    uint8_t data[] = {42, 43, 44};
    uint8_t* ptr = write_uint16_length_data(buffer, data, 3);
    NABTO_TEST_CHECK(uint16_read(buffer) == 3);
    NABTO_TEST_CHECK(buffer[2] == 42);
    NABTO_TEST_CHECK(buffer[3] == 43);
    NABTO_TEST_CHECK(buffer[4] == 44);
    NABTO_TEST_CHECK(ptr == buffer + 5);
}

void nc_packet_tests()
{
    nc_packet_test_uint16_write_forward();
    nc_packet_test_uint16_read_write();
    nc_packet_test_init_packet_header();
    nc_packet_test_insert_packet_ext();
    nc_packet_test_write_length_data();
}
