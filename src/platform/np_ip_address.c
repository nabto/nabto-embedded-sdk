#include "np_ip_address.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

bool np_ip_is_v4(const struct np_ip_address* ip)
{
    return (ip->type == NABTO_IPV4);
}

bool np_ip_is_v6(const struct np_ip_address* ip)
{
    return (ip->type == NABTO_IPV6);
}

const char* np_ip_address_to_string(const struct np_ip_address* address)
{
    static char outputBuffer[40]; // 8*4 + 7 + 1
    memset(outputBuffer, 0, 40);
    if (address->type == NABTO_IPV4) {
        const uint8_t* ip = address->ip.v4;
        sprintf(outputBuffer, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8, ip[0], ip[1], ip[2], ip[3]);
    } else if (address->type == NABTO_IPV6) {
        const uint8_t* ip = address->ip.v6;
        sprintf(outputBuffer, "%02X%02X:" "%02X%02X:" "%02X%02X:" "%02X%02X:" "%02X%02X:" "%02X%02X:" "%02X%02X:" "%02X%02X", ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
    }
    return outputBuffer;
}

void np_ip_address_assign_v4(struct np_ip_address* ip, uint32_t address)
{
    ip->type = NABTO_IPV4;
    ip->ip.v4[0] = (uint8_t)(address >> 24);
    ip->ip.v4[1] = (uint8_t)(address >> 16);
    ip->ip.v4[2] = (uint8_t)(address >> 8);
    ip->ip.v4[3] = (uint8_t)(address);
}

static const uint8_t ipv4MappedIpv6Prefix[12] = {0x00,0x00,0x00,0x00,
                                                 0x00,0x00,0x00,0x00,
                                                 0x00,0x00,0xFF,0xFF};
bool np_ip_is_v4_mapped(const struct np_ip_address* ip)
{
    if (np_ip_is_v6(ip)) {
        const uint8_t* ptr = ip->ip.v6;
        if (memcmp(ptr, ipv4MappedIpv6Prefix, 12) == 0) {
            return true;
        }
    }
    return false;
}

void np_ip_convert_v4_to_v4_mapped(const struct np_ip_address* v4, struct np_ip_address* v6)
{
    // convert v4 to v4 mapped ipv6 address.  ipv4 mapped ipv6
    // addresses consist of the prefix 0:0:0:0:0:FFFF and then the
    // ipv4 address.
    v6->type = NABTO_IPV6;
    uint8_t* ptr = v6->ip.v6;
    // 80 bits of zeroes
    memcpy(ptr, ipv4MappedIpv6Prefix, 12);
    memcpy(ptr + 12, v4->ip.v4, 4);
}

void np_ip_convert_v4_mapped_to_v4(const struct np_ip_address* v6, struct np_ip_address* v4)
{
    v4->type = NABTO_IPV4;
    memcpy(v4->ip.v4, v6->ip.v6+12, 4);
}
