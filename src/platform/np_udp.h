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

struct np_udp_module {

    /**
     * create an UDP socket resource. If create returns NABTO_EC_OK,
     * destroy must be called when socket is no longer in use to clean
     * up the resource.
     */
    np_error_code (*create)(struct np_platform* pl, np_udp_socket** sock);

    /**
     * Destroy a socket. This will close everything and clean up
     * resources. No outstanding callbacks will be resolved.
     */
    void (*destroy)(np_udp_socket* sock);

    /**
     * Abort outstanding async operations on the socket resolving all
     * callbacks. No further reads or writes are possible. Once all
     * callbacks are resolved, the socket should be destroyed. All
     * callbacks are resolved asynchronously.
     */
    np_error_code (*abort)(np_udp_socket* sock);

    /**
     * Create a udp socket and bind it to a port. Port 0 means ephemeral.
     */
    np_error_code (*async_bind_port)(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data);

    /**
     * Optional create function which creates a mdns ready socket.
     * The socket is bound to 5353 and uses has the REUSEPORT flag set.
     */
    np_error_code (*async_bind_mdns_ipv4)(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);

    /**
     * Optional create function which creates a mdns ready socket.
     * The socket is bound to 5353 and uses has the REUSEPORT flag set.
     */
    np_error_code (*async_bind_mdns_ipv6)(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);

    /**
     * Send packet async. It's the responsibility of the caller to
     * keep the ep and buffer alive until the callback is invoked.
     */
    np_error_code (*async_send_to)(np_udp_socket* sock, struct np_udp_endpoint ep,
                                   uint8_t* buffer, uint16_t bufferSize,
                                   np_udp_packet_sent_callback cb, void* userData);

    /**
     * Receive a packet async. If the socket is broken an error is
     * returned.
     */
    np_error_code (*async_recv_from)(np_udp_socket* socket, np_udp_packet_received_callback cb, void* data);

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
