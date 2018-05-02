#ifndef NABTO_ERROR_CODE_H
#define NABTO_ERROR_CODE_H

// TODO use categories.

typedef enum {
    NABTO_EC_OK = 0,
    NABTO_EC_UDP_SOCKET_CREATION_ERROR,
    NABTO_EC_INVALID_SOCKET,
    NABTO_EC_FAILED_TO_SEND_PACKET
} nabto_error_code;


#endif
