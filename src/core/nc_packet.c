
#include "nc_packet.h"

#include <platform/np_logging.h>

#include <string.h>

bool var_uint_read(uint8_t* buf, uint16_t bufSize, uint64_t* val, uint8_t* len)
{
    *val = 0;
    *len = 0;
    uint8_t first = *buf;
    uint8_t b7 = first & 0x3F; // 00111111
    uint8_t lengthBits = first >> 6;
    if (bufSize < (size_t)(1 << lengthBits)) {
        return false;
    }

    if (lengthBits == 0) {
        *val = b7;
        *len = 1;
    } else if (lengthBits == 1) {
        uint8_t b6 = buf[1];
        *val =
            ((uint64_t)b7 << 8) +
            ((uint64_t)b6);
        *len = 2;
    } else  if (lengthBits == 2) {
        uint8_t b6 = buf[1];
        uint8_t b5 = buf[2];
        uint8_t b4 = buf[3];
        *val =
            ((uint64_t)b7 << 24) +
            ((uint64_t)b6 << 16) +
            ((uint64_t)b5 << 8) +
            ((uint64_t)b4);
        *len = 4;
    } else if (lengthBits == 3) {
        uint8_t b6 = buf[1];
        uint8_t b5 = buf[2];
        uint8_t b4 = buf[3];
        uint8_t b3 = buf[4];
        uint8_t b2 = buf[5];
        uint8_t b1 = buf[6];
        uint8_t b0 = buf[7];

        *val =
            ((uint64_t)b7 << 56) +
            ((uint64_t)b6 << 48) +
            ((uint64_t)b5 << 40) +
            ((uint64_t)b4 << 32) +
            ((uint64_t)b3 << 24) +
            ((uint64_t)b2 << 16) +
            ((uint64_t)b1 << 8) +
            ((uint64_t)b0);
        *len = 8;
    }
    return true;

}

uint8_t* var_uint_write_forward(uint8_t* buf, uint64_t val)
{
    uint8_t lengthBits = 0;
    uint8_t b7 = (uint8_t)(val);
    uint8_t b6 = (uint8_t)(val >> 8);
    uint8_t b5 = (uint8_t)(val >> 16);
    uint8_t b4 = (uint8_t)(val >> 24);
    uint8_t b3 = (uint8_t)(val >> 32);
    uint8_t b2 = (uint8_t)(val >> 40);
    uint8_t b1 = (uint8_t)(val >> 48);
    uint8_t b0 = (uint8_t)(val >> 56);

    if (val < (1 << 6)) { // val fits in 6 bits
        lengthBits = 0x00; // 00xxxxxx
        *buf = b7;
        buf++;
    } else if (val < (1 << 14)) { // val fits in 14 bits
        lengthBits = 1 << 6; // 01xxxxxx
        *buf = b6 | lengthBits;
        buf++;
        *buf = b7;
        buf++;
    } else if (val < (1 << 30)) { // val fits in 30 bits
        lengthBits = 2 << 6; // 10xxxxxx
        *buf = b4 | lengthBits;
        buf++;
        *buf = b5;
        buf++;
        *buf = b6;
        buf++;
        *buf = b7;
        buf++;
    } else { // all 64 bits are needed
        lengthBits = 3 << 6; // 11xxxxxx
        *buf = b0 | lengthBits;
        buf++;
        *buf = b1;
        buf++;
        *buf = b2;
        buf++;
        *buf = b3;
        buf++;
        *buf = b4;
        buf++;
        *buf = b5;
        buf++;
        *buf = b6;
        buf++;
        *buf = b7;
        buf++;
    }
    return buf;
}
