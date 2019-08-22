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
    // TODO anonymous unions is not c89 or c99
    union {
        struct np_ipv4_address v4;
        struct np_ipv6_address v6;
    };
};

bool np_ip_is_v4(struct np_ip_address* ip);

bool np_ip_is_v6(struct np_ip_address* ip);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
