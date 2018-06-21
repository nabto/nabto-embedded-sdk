#include "nc_protocol_defines.h"

#include <platform/np_platform.h>

uint8_t* uint16_write_forward(uint8_t* buf, uint16_t val);

uint8_t* init_packet_header(uint8_t* buf, enum application_data_type ad);

uint8_t* insert_packet_extension(struct np_platform* pl, np_communication_buffer* buf, enum extension_type et, uint8_t* data, uint16_t dataLen);

void uint16_write(uint8_t* buf, uint16_t val);

uint16_t uint16_read(uint8_t* buf);

uint8_t* write_uint16_length_data(uint8_t* buf, uint8_t* data, uint16_t size);
