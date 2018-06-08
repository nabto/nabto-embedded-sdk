#ifndef _NC_PROTOCOL_DEFINES_H_
#define _NC_PROTOCOL_DEFINES_H_

#ifndef NABTO_PACKET_HEADER_SIZE
#define NABTO_PACKET_HEADER_SIZE 4
#endif

enum application_data_type {
    ATTACH_DISPATCH = 1,
    ATTACH = 2,
    RELAY = 3,
    KEEP_ALIVE = 4
};

enum attach_dispatch_content_type {
    ATTACH_DISPATCH_REQUEST = 1,
    ATTACH_DISPATCH_REDIRECT = 2,
    ATTACH_DISPATCH_RESPONSE = 3
};

enum attach_content_type {
    ATTACH_DEVICE_HELLO = 1,
    ATTACH_SERVER_HELLO = 2,
};

enum keep_alive_content_type {
    KEEP_ALIVE_SETTINGS = 1,
    KEEP_ALIVE_SETTINGS_ACK = 2,
    KEEP_ALIVE_REQUEST = 3,
    KEEP_ALIVE_RESPONSE = 4
};

enum extension_type {
    UDP_DNS_EP = 0x0001,
    UDP_IPV4_EP = 0x0002,
    UDP_IPV6_EP = 0x0003,
    SUPPORTED_VERSIONS = 0x0004
};

#endif // _NC_PROTOCOL_DEFINES_H_
