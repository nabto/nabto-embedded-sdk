#ifndef NP_ERROR_CODE_H
#define NP_ERROR_CODE_H

// TODO use categories.

typedef enum {
    NABTO_EC_OK = 0,
    NABTO_EC_FAILED,
    NABTO_EC_UDP_SOCKET_CREATION_ERROR,
    NABTO_EC_UDP_SOCKET_ERROR,
    NABTO_EC_INVALID_SOCKET,
    NABTO_EC_FAILED_TO_SEND_PACKET,
    NABTO_EC_MALFORMED_PACKET,
    NABTO_EC_OUT_OF_CHANNELS,
    NABTO_EC_OUT_OF_CONNECTIONS,
    NABTO_EC_INVALID_CHANNEL,
    NABTO_EC_INVALID_CONNECTION_ID,
    NABTO_EC_INVALID_PACKET_TYPE,
    NABTO_EC_INSUFFICIENT_BUFFER_ALLOCATION,
    NABTO_EC_ALPN_FAILED,
    NABTO_EC_INVALID_PEER_FINGERPRINT
} np_error_code;


#endif
