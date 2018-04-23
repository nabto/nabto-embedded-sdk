#ifndef NABTO_IP_ADDRESS_H
#define NABTO_IP_ADDRESS_H

#include <platform/types.h>

enum nabto_ip_address_type {
    NABTO_IPV4,
    NABTO_IPV6
};


// network order ip address
struct nabto_ipv4_address {
    uint8_t addr[4];
};

// network order ipv6 address
struct nabto_ipv6_address {
    uint8_t addr[16];
};

struct nabto_ip_address {
    enum nabto_ip_address_type type;
    union {
        struct nabto_ipv4_address v4;
        struct nabto_ipv6_address v6;
    };
};

struct nabto_udp_endpoint {
    struct nabto_ip_address ip;
    uint16_t port;
};

bool nabto_ip_is_v4(struct nabto_ip_address* ip);

bool nabto_ip_is_v6(struct nabto_ip_address* ip);

#endif
