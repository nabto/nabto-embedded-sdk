#ifndef NP_IP_ADDRESS_H
#define NP_IP_ADDRESS_H

#include <platform/np_types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum np_ip_address_type {
    NABTO_IPV4,
    NABTO_IPV6
};


// network order ip address
struct np_ipv4_address {
    uint8_t addr[4];
};

// network order ipv6 address
struct np_ipv6_address {
    uint8_t addr[16];
};

struct np_ip_address {
    enum np_ip_address_type type;
    union {
        uint8_t v4[4];
        uint8_t v6[16];
    } ip;
};

bool np_ip_is_v4(const struct np_ip_address* ip);

bool np_ip_is_v6(const struct np_ip_address* ip);

/**
 * Return true if the ip address is an ipv4 mapped ipv6 address.
 */
bool np_ip_is_v4_mapped(const struct np_ip_address* ip);

/**
 * Convert an ipv4 address to an ipv6 mapped ipv4 address.
 */
void np_ip_convert_v4_to_v4_mapped(const struct np_ip_address* v4, struct np_ip_address* v6);

/**
 * Convert an v4 mapped ipv6 address to an ipv4 address.
 */
void np_ip_convert_v4_mapped_to_v4(const struct np_ip_address* v6, struct np_ip_address* v4);

/**
 * print the ip into a null terminated static buffer. This buffer is
overwritten next time this function is called.
*/
const char* np_ip_address_to_string(const struct np_ip_address* ip);

/**
 * assign ipv4 address in host byte order to the ip address.
 */
void np_ip_address_assign_v4(struct np_ip_address* ip, uint32_t address);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
