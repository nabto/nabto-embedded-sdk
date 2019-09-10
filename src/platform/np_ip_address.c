#include "np_ip_address.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

bool np_ip_is_v4(struct np_ip_address* ip)
{
    return (ip->type == NABTO_IPV4);
}

bool np_ip_is_v6(struct np_ip_address* ip)
{
    return (ip->type == NABTO_IPV6);
}

const char* np_ip_address_to_string(struct np_ip_address* address)
{
    static char outputBuffer[40]; // 8*4 + 7 + 1
    memset(outputBuffer, 0, 40);
    if (address->type == NABTO_IPV4) {
        const uint8_t* ip = address->v4.addr;
        sprintf(outputBuffer, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8, ip[0], ip[1], ip[2], ip[3]);
    } else if (address->type == NABTO_IPV6) {
        const uint8_t* ip = address->v6.addr;
        sprintf(outputBuffer, "%02X%02X:" "%02X%02X:" "%02X%02X:" "%02X%02X:" "%02X%02X:" "%02X%02X:" "%02X%02X:" "%02X%02X", ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
    }
    return outputBuffer;
}
