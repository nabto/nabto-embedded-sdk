#include "nc_protocol_defines.h"

#include <platform/np_platform.h>

uint8_t* uint16_write_forward(uint8_t* buf, uint16_t val);

uint8_t* init_packet_header(uint8_t* buf, enum application_data_type ad);

void insert_packet_extension(struct np_platform* pl, np_communication_buffer* buf, enum extension_type et, uint8_t* data, uint16_t dataLen);

uint16_t uint16_read(uint8_t* buf);
