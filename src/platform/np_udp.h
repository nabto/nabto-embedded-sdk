#ifndef NP_UDP_H
#define NP_UDP_H

typedef struct np_udp_endpoint np_udp_endpoint;
typedef struct np_udp_socket np_udp_socket;

#include <core/nc_protocol_defines.h>
#include <platform/np_ip_address.h>
#include <platform/np_error_code.h>
#include <platform/np_communication_buffer.h>

struct np_platform;

struct np_udp_endpoint {
    struct np_ip_address ip;
    uint16_t port;
};

typedef void (*np_udp_socket_created_callback)(const np_error_code ec, np_udp_socket* socket, void* data);

typedef void (*np_udp_packet_sent_callback)(const np_error_code ec, void* data);

typedef void (*np_udp_packet_received_callback)(const np_error_code ec, struct np_udp_endpoint ep, np_communication_buffer* buffer, uint16_t bufferSize, void* data);

typedef void (*np_udp_socket_destroyed_callback)(const np_error_code ec, void* data);

struct np_udp_module {
    /**
     * Create a udp socket. The socket is bound to an ephemeral port.
     */
    void (*async_create)(np_udp_socket_created_callback cb, void* data);

    /**
     * Create a udp socket and bind it to a port.
     */
    void (*async_bind_port)(uint16_t port, np_udp_socket_created_callback cb, void* data);

    /**
     * Send packet async. It's the responsibility of the caller to
     * keep the ep and buffer alive until the callback is invoked.
     */
    void (*async_send_to)(np_udp_socket* socket, struct np_udp_endpoint* ep, np_communication_buffer* buffer, uint16_t bufferSize, np_udp_packet_sent_callback cb, void* data);

    /**
     * Receive a packet async. If the socket is broken an error is returned.
     */
    void (*async_recv_from)(np_udp_socket* socket, enum np_channel_type type, np_udp_packet_received_callback cb, void* data);

    /**
     * Cancel previous call to async_recv_from
     */
    void (*cancel_recv_from)(np_udp_socket* socket, enum np_channel_type type);
    
    /**
     * Cancel previous call to async_send_to
     */
    void (*cancel_send_to)(np_udp_socket* socket, enum np_channel_type type);
    
    /**
     * Get the IP protocol of the socket.
     */
    enum np_ip_address_type (*get_protocol)(np_udp_socket* socket);
    
    /**
     * Destroy a socket. This will stop any outstanding send/receive operation.
     */
    void (*async_destroy)(np_udp_socket* socket, np_udp_socket_destroyed_callback cb, void* data);
    
};


#endif
