#ifndef NC_PROTOCOL_DEFINES_H
#define NC_PROTOCOL_DEFINES_H

enum np_protocol_prefix {
    NABTO_PROTOCOL_PREFIX_CONNECTION = 240,
    NABTO_PROTOCOL_PREFIX_RENDEZVOUS = 241
};

enum application_data_type {
    AT_KEEP_ALIVE   = 0x04,
    AT_STREAM       = 0x05,
    AT_RENDEZVOUS   = 0x07,
    AT_COAP_START   = 0b01000000,
    AT_COAP_END     = 0b01111111
};

enum keep_alive_content_type {
    CT_KEEP_ALIVE_REQUEST      = 0x03,
    CT_KEEP_ALIVE_RESPONSE     = 0x04
};

enum rendezvous_content_type {
    CT_RENDEZVOUS_CLIENT_REQUEST  = 0x01,
    CT_RENDEZVOUS_CLIENT_RESPONSE = 0x02,
    CT_RENDEZVOUS_DEVICE_REQUEST = 0x03
};

enum attach_status {
    ATTACH_STATUS_ATTACHED = 0x00,
    ATTACH_STATUS_REDIRECT = 0x01
};

#endif // _NC_PROTOCOL_DEFINES_H_
