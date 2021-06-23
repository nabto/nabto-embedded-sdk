#include "np_util.h"

bool np_hex_to_data(const char* hex, uint8_t* data, size_t dataLength)
{
    size_t hexLength = strlen(hex);
    return np_hex_to_data_length(hex, hexLength, data, dataLength);
}

bool np_hex_to_data_length(const char* hex, size_t hexLength, uint8_t* data, size_t dataLength)
{
    // hexLength should be 2*datalength or (2*dataLength - 1)
    if (!(hexLength == dataLength * 2 ||
          hexLength == ((dataLength * 2) - 1)))
    {
        return false;
    }
    memset(data, 0, dataLength);

    size_t index = 0;

    const char* end = hex + hexLength;
    const char* ptr = hex;

    if (hexLength % 2 == 1) {
        // odd number of hexadecimal chars, assume the first is an implicit 0
        // 0x1 = 0x01 = 1
        index = 1;
    }

    while (ptr < end) {
        char c = *ptr;
        uint8_t value = 0;
        if(c >= '0' && c <= '9')
          value = (c - '0');
        else if (c >= 'A' && c <= 'F')
          value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
          value = (10 + (c - 'a'));
        else {
            return false;
        }

        // shift each even hex byte 4 up
        data[(index/2)] += value << (((index + 1) % 2) * 4);

        index++;
        ptr++;
    }

    return true;
}

// assume val <= 15
static char encodeChar(uint8_t val)
{
    if (val <= 9) {
        return '0' + val;
    } else {
        return 'a' + (val - 10);
    }
}

void np_data_to_hex(uint8_t* data, size_t dataLength, char* output)
{
    size_t i;
    for (i = 0; i < dataLength; i++) {
        uint8_t byte = data[i];

        uint8_t high = (byte >> 4) & 0xF;
        uint8_t low  = byte & 0xF;

        output[(i*2)] = encodeChar(high);
        output[(i*2)+1] = encodeChar(low);
    }
}
