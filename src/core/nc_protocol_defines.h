#ifndef NC_PROTOCOL_DEFINES_H
#define NC_PROTOCOL_DEFINES_H

#ifndef NABTO_PACKET_HEADER_SIZE
#define NABTO_PACKET_HEADER_SIZE 2
#endif

enum np_channel_type {
    NABTO_CHANNEL_DTLS = 1,
    NABTO_CHANNEL_STUN = 2,
    NABTO_CHANNEL_APP = 3
};

enum application_data_type {
    AT_DEVICE_LB    = 0x01,
    AT_DEVICE_RELAY = 0x02,
    AT_CLIENT_RELAY = 0x03,
    AT_KEEP_ALIVE   = 0x04,
    AT_STREAM       = 0x05
};

enum attach_dispatch_content_type {
    CT_DEVICE_LB_REQUEST  = 0x01,
    CT_DEVICE_LB_REDIRECT = 0x02,
    CT_DEVICE_LB_RESPONSE = 0x03
};

enum attach_content_type {
    CT_DEVICE_RELAY_HELLO_REQUEST  = 0x01,
    CT_DEVICE_RELAY_HELLO_RESPONSE = 0x02,
};

enum keep_alive_content_type {
    CT_KEEP_ALIVE_SETTINGS     = 0x01,
    CT_KEEP_ALIVE_SETTINGS_ACK = 0x02,
    CT_KEEP_ALIVE_REQUEST      = 0x03,
    CT_KEEP_ALIVE_RESPONSE     = 0x04
};

enum extension_type {
    EX_UDP_DNS_EP          = 0x0001,
    EX_UDP_IPV4_EP         = 0x0002,
    EX_UDP_IPV6_EP         = 0x0003,
    EX_DTLS_EP             = 0x0004,
    EX_KEEP_ALIVE_SETTINGS = 0x0005,
    EX_NABTO_VERSION       = 0x0006,
    EX_APPLICATION_NAME    = 0x0007,
    EX_UNKNOWN_CONNECTION  = 0x0008,
    EX_APPLICATION_VERSION = 0x0009,
    EX_SESSION_ID          = 0x000a,
    EX_ATTACH_INDEX        = 0x000b
};

#endif // _NC_PROTOCOL_DEFINES_H_
