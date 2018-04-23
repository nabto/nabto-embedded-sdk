#ifndef UNABTO_IP_ADDRESS_H
#define UNABTO_IP_ADDRESS_H

#include <platform/types.h>

enum unabto_ip_address_type {
    UNABTO_IPV4,
    UNABTO_IPV6
};


// network order ip address
struct unabto_ipv4_address {
    uint8_t addr[4];
};

// network order ipv6 address
struct unabto_ipv6_address {
    uint8_t addr[16];
};

struct unabto_ip_address {
    enum unabto_ip_address_type type;
    union {
        struct unabto_ipv4_address v4;
        struct unabto_ipv6_address v6;
    };
};

struct unabto_udp_endpoint {
    struct unabto_ip_address ip;
    uint16_t port;
};

bool unabto_ip_is_v4(struct unabto_ip_address* ip);

bool unabto_ip_is_v6(struct unabto_ip_address* ip);

#endif
