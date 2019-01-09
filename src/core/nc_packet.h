#include "nc_protocol_defines.h"

#include <platform/np_platform.h>

uint8_t* init_packet_header(uint8_t* buf, enum application_data_type ad);
uint8_t* insert_packet_extension(struct np_platform* pl, uint8_t* buf, enum extension_type et, uint8_t* data, uint16_t dataLen);

uint8_t* var_uint_write_forward(uint8_t* buf, uint64_t val);
bool var_uint_read(uint8_t* buf, uint16_t bufSize, uint64_t* val, uint8_t* len);

uint8_t* uint16_write_forward(uint8_t* buf, uint16_t val);
uint8_t* uint32_write_forward(uint8_t* buf, uint32_t val);
void uint16_write(uint8_t* buf, uint16_t val);
uint8_t* write_uint16_length_data(uint8_t* buf, uint8_t* data, uint16_t size);

uint16_t uint16_read(uint8_t* buf);
uint32_t uint32_read(uint8_t* buf);

uint8_t* udp_ep_ext_write_forward(uint8_t* buf, struct np_udp_endpoint* ep);

