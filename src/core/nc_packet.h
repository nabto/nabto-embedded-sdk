#ifndef NC_PACKET_H
#define NC_PACKET_H

#include "nc_protocol_defines.h"

#include <platform/np_platform.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t* var_uint_write_forward(uint8_t* buf, uint64_t val);
bool var_uint_read(uint8_t* buf, uint16_t bufSize, uint64_t* val, uint8_t* len);

#ifdef __cplusplus
} // extern c
#endif

#endif
