
#include "nc_packet.h"

#include <platform/np_logging.h>

#include <string.h>

uint8_t* uint16_write_forward(uint8_t* buf, uint16_t val)
{
    uint16_write(buf, val);
    return buf+2;
}

uint8_t* uint32_write_forward(uint8_t* buf, uint32_t val)
{
    uint8_t d0 = (uint8_t)(((val) >> 24) & 0xff);
    uint8_t d1 = (uint8_t)(((val) >> 16) & 0xff);
    uint8_t d2 = (uint8_t)(((val) >> 8)  & 0xff);
    uint8_t d3 = (uint8_t)( (val)        & 0xff);
    *buf = d0;
    buf++;
    *buf = d1;
    buf++;
    *buf = d2;
    buf++;
    *buf = d3;
    buf++;
    return buf;    
}

void uint16_write(uint8_t* buf, uint16_t val)
{
    uint8_t d0 = (uint8_t)(((val) >> 8) & 0xff);
    uint8_t d1 = (uint8_t)( (val)       & 0xff);
    *buf = d0;
    buf++;
    *buf = d1;
}

uint16_t uint16_read(uint8_t* buf)
{
    uint16_t res = *buf << 8;
    return res + *(buf+1);
}

uint32_t uint32_read(uint8_t* buf)
{
    uint32_t res = buf[0] << 24;
    res = res + buf[1] << 16;
    res = res + buf[2] << 8;
    res = res + buf[3];
    return res;
}

uint8_t* init_packet_header(uint8_t* buf, enum application_data_type ad)
{
    *buf = (uint8_t)ad;
    buf++;
    *buf = 0;
    return ++buf;
}

uint8_t* insert_packet_extension(struct np_platform* pl, uint8_t* buf, enum extension_type et, uint8_t* data, uint16_t dataLen)
{
    buf = uint16_write_forward(buf, et);
    buf = uint16_write_forward(buf, dataLen);
    memcpy(buf, data, dataLen);
    return buf+dataLen;
}

uint8_t* write_uint16_length_data(uint8_t* buf, uint8_t* data, uint16_t size)
{
    uint16_write(buf, size);
    memcpy(buf+2, data, size);
    return buf+2+size;
}
