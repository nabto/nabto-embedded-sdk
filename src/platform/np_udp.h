#ifndef NP_UDP_H
#define NP_UDP_H

typedef struct np_udp_endpoint np_udp_endpoint;
typedef struct np_udp_socket np_udp_socket;

#include <core/nc_protocol_defines.h>
#include <platform/np_ip_address.h>
#include <platform/np_error_code.h>
#include <platform/np_communication_buffer.h>
#include <platform/np_event_queue.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;

struct np_udp_endpoint {
    struct np_ip_address ip;
    uint16_t port;
};

typedef void (*np_udp_socket_created_callback)(const np_error_code ec, void* data);

typedef void (*np_udp_packet_sent_callback)(const np_error_code ec, void* data);

typedef void (*np_udp_packet_received_callback)(const np_error_code ec, struct np_udp_endpoint ep,
                                                uint8_t* buffer, uint16_t bufferSize, void* data);

typedef void (*np_udp_socket_destroyed_callback)(const np_error_code ec, void* data);

struct np_udp_send_context {
    np_udp_socket* sock;
    struct np_udp_endpoint ep;
    uint8_t* buffer;
    uint16_t bufferSize;
    np_udp_packet_sent_callback cb;
    void* cbData;
    struct np_event ev;
};

void np_udp_populate_send_context(struct np_udp_send_context* ctx, np_udp_socket* sock,
                                  struct np_udp_endpoint ep,
                                  uint8_t* buffer, uint16_t bufferSize,
                                  np_udp_packet_sent_callback cb, void* data);
struct np_udp_module {

    np_error_code (*create)(struct np_platform* pl, np_udp_socket** sock);

    /**
     * Destroy a socket. This will stop any outstanding send/receive
     * operation.
     */
    void (*destroy)(np_udp_socket* sock);

    /**
     * Create a udp socket. The socket is bound to an ephemeral port.
     */
    void (*async_bind)(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);

    /**
     * Create a udp socket and bind it to a port.
     */
    void (*async_bind_port)(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data);

    /**
     * Optional create function which creates a mdns ready socket.
     * The socket is bound to 5353 and uses has the REUSEPORT flag set.
     */
    void (*async_bind_mdns_ipv4)(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);

    /**
     * Optional create function which creates a mdns ready socket.
     * The socket is bound to 5353 and uses has the REUSEPORT flag set.
     */
    void (*async_bind_mdns_ipv6)(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);

    /**
     * Send packet async. It's the responsibility of the caller to
     * keep the ep and buffer alive until the callback is invoked.
     */
    void (*async_send_to)(struct np_udp_send_context* ctx);

    /**
     * Receive a packet async. If the socket is broken an error is
     * returned.
     */
    void (*async_recv_from)(np_udp_socket* socket, np_udp_packet_received_callback cb, void* data);

    /**
     * Get the IP protocol of the socket.
     */
    enum np_ip_address_type (*get_protocol)(np_udp_socket* socket);

    /**
     * Get the local IP address.
     * @param addrs     Pointer to an ip_address array of size addrsSize
     * @param addrsSize size of addrs
     * @return number of ip addresses put into the array
     */
    size_t (*get_local_ip)( struct np_ip_address *addrs, size_t addrsSize);

    /**
     * Get the local port number
     */
    uint16_t (*get_local_port)(np_udp_socket* socket);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
