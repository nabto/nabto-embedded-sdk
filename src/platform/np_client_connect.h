#ifndef NP_CLIENT_CONNECT_H
#define NP_CLIENT_CONNECT_H

#include <platform/np_udp.h>
#include <platform/np_connection.h>
#include <nabto_types.h>

struct np_platform;

struct np_client_connect_module {
    np_error_code (*new)(struct np_platform* pl, enum np_channel_type type, uint8_t* id,
                         uint8_t idSize, struct np_udp_socket* sock, np_udp_endpoint* ep);
    np_connection* (*get)(struct np_platform* pl, struct np_connection_id id);
    np_error_code (*recv)(const np_error_code ec, struct np_udp_endpoint ep,
                          np_communication_buffer* buffer, uint16_t bufferSize);
};

#endif //NP_CLIENT_CONNECT_H
