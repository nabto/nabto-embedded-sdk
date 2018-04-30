#ifndef NABTO_UDP_H
#define NABTO_UDP_H

#include <platform/error_code.h>
#include <platform/communication_buffer.h>
#include <platform/ip_address.h>

typedef struct nabto_udp_socket_ {
} nabto_udp_socket;

typedef void (*nabto_udp_socket_created_callback)(const nabto_error_code ec, nabto_udp_socket* socket, void* data);

typedef void (*nabto_udp_packet_sent_callback)(const nabto_error_code ec, void* data);

typedef void (*nabto_udp_packet_received_callback)(const nabto_error_code ec, struct nabto_udp_endpoint ep, nabto_communication_buffer* buffer, void* data);

typedef void (*nabto_udp_socket_destroyed_callback)(const nabto_error_code ec, void* data);

struct nabto_udp_module {
    /**
     * Create a udp socket. The socket is bound to an ephemeral port.
     */
    void (*async_create)(nabto_udp_socket_created_callback cb, void* data);

    /**
     * Create a udp socket and bind it to a port.
     */
    void (*async_bind_port)(uint16_t port, nabto_udp_socket_created_callback cb, void* data);

    /**
     * Send packet async. It's the responsibility of the caller to
     * keep the ep and buffer alive until the callback is invoked.
     */
    void (*async_send_to)(nabto_udp_socket* socket, struct nabto_udp_endpoint* ep, uint8_t* buffer, uint16_t bufferSize, nabto_udp_packet_sent_callback cb, void* data);

    /**
     * Receive a packet. If the socket is broken an error is returned.
     */
    void (*async_recv_from)(nabto_udp_socket* socket, nabto_udp_packet_received_callback cb, void* data);

    /**
     * Destroy a socket. This will stop any outstanding send/receive operation.
     */
    void (*async_destroy)(nabto_udp_socket* socket, nabto_udp_socket_destroyed_callback cb, void* data);
    
};


#endif
