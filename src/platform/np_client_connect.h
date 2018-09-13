#ifndef NP_CLIENT_CONNECT_H
#define NP_CLIENT_CONNECT_H

#include <platform/np_udp.h>
#include <platform/np_connection.h>
#include <platform/np_dtls_srv.h>
#include <nabto_types.h>

struct np_platform;

#define NABTO_MAX_CLIENT_CONNECTIONS 8

typedef void (*np_client_connect_created_callback)(const np_error_code ec, struct np_dtls_srv_connection* dtls, void* data);
typedef void (*np_client_connect_close_callback)(const np_error_code ec, void* data);

struct np_client_connect_module {
    np_error_code (*async_create)(struct np_platform* pl, struct np_connection_id* id,
                                  struct np_udp_socket* sock, np_udp_endpoint* ep,
                                  np_client_connect_created_callback cb, void* data);
    np_connection* (*get_connection)(struct np_platform* pl, struct np_connection_id* id);
    np_error_code (*recv)(struct np_platform* pl, const np_error_code ec, struct np_udp_socket* sock, struct np_udp_endpoint ep,
                          np_communication_buffer* buffer, uint16_t bufferSize);
    np_error_code (*async_recv_from)(np_connection* conn, np_udp_packet_received_callback cb, void* data);
    np_error_code (*async_close)(struct np_platform* pl, struct np_connection_id* id, np_client_connect_close_callback cb, void* data);
};

#endif //NP_CLIENT_CONNECT_H
