#ifndef NC_PROTOCOL_DEFINES_H
#define NC_PROTOCOL_DEFINES_H

#ifndef NABTO_PACKET_HEADER_SIZE
#define NABTO_PACKET_HEADER_SIZE 2
#endif

// TODO: 
/* These are not actual multiplexing ids, but rather abstract
 * values. In practice, the DTLS id is the range [20; 64], STUN is
 * range [0;1] and APP is range [240; 255]. This should be fixed in
 * the future to simplify udp dispatching. Possibly so
 * udp.async_recv_from takes a range for which IDs to recv from.
 */
enum np_protocol_multiplexing_id {
    NABTO_PROTOCOL_ID_DTLS = 1,
    NABTO_PROTOCOL_ID_STUN = 2,
    NABTO_PROTOCOL_ID_APP = 3,
    NABTO_PROTOCOL_ID_PROBE = 4
};

enum np_protocol_prefix {
    NABTO_PROTOCOL_PREFIX_CONNECTION = 240,
    NABTO_PROTOCOL_PREFIX_RENDEZVOUS = 241
};

enum application_data_type {
    AT_DEVICE_LB    = 0x01,
    AT_DEVICE_RELAY = 0x02,
    AT_CLIENT_RELAY = 0x03,
    AT_KEEP_ALIVE   = 0x04,
    AT_STREAM       = 0x05,
    AT_RENDEZVOUS_CONTROL = 0x06,
    AT_RENDEZVOUS   = 0x07,
    AT_COAP_START   = 0b01000000,
    AT_COAP_END     = 0b01111111
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

enum rendezvous_content_type {
    CT_RENDEZVOUS_CLIENT_REQUEST  = 0x01,
    CT_RENDEZVOUS_CLIENT_RESPONSE = 0x02,
    CT_RENDEZVOUS_DEVICE_REQUEST = 0x03
};

enum rendezvous_ctrl_content_type {
    CT_RENDEZVOUS_CTRL_STUN_START_REQ  = 0x04,
    CT_RENDEZVOUS_CTRL_STUN_START_RESP = 0x05,
    CT_RENDEZVOUS_CTRL_STUN_DATA_REQ   = 0x06,
    CT_RENDEZVOUS_CTRL_STUN_DATA_RESP  = 0x07,
    CT_RENDEZVOUS_CTRL_REQUEST         = 0x08
};

enum attach_status {
    ATTACH_STATUS_ATTACHED = 0x00,
    ATTACH_STATUS_REDIRECT = 0x01
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
    EX_ATTACH_INDEX        = 0x000b,
    EX_STUN_RESULT_IPV4    = 0x000c,
    EX_STUN_DEFECT_FIREWALL = 0x000d,
    EX_ATTACH_STATUS       = 0x000e
};

#endif // _NC_PROTOCOL_DEFINES_H_
