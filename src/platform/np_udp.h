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
     *
     * @param completionEvent event to be resolved when the socket is bound
     */
    void (*async_bind_port)(np_udp_socket* sock, uint16_t port, struct np_event_ec* completionEvent);

    /**
     * Optional create function which creates a mdns ready socket.
     * The socket is bound to 5353 and uses has the REUSEPORT flag set.
     */
    void (*async_bind_mdns_ipv4)(np_udp_socket* sock, struct np_event_ec* completionEvent);

    /**
     * Optional create function which creates a mdns ready socket.
     * The socket is bound to 5353 and uses has the REUSEPORT flag set.
     */
    void (*async_bind_mdns_ipv6)(np_udp_socket* sock, struct np_event_ec* completionEvent);

    /**
     * Send packet async. It's the responsibility of the caller to
     * keep the ep and buffer alive until the callback is invoked.
     */
    void (*async_send_to)(np_udp_socket* sock, struct np_udp_endpoint ep,
                          uint8_t* buffer, uint16_t bufferSize,
                          struct np_event* completionEvent);

    /**
     * Wait for a packet to be ready to be received. This needs to be
     * combined with recv_from.
     *
     * The reason for splitting recv_from up into two functions is
     * that the recv_from operation can take a long time, we do not
     * want to occupy a recv buffer for that long time. On systems
     * without events like select, epoll, kqueue the recv_from adapter
     * code can store a buffered copy of the packet between the
     * completionEvent is resolved and recv_from is called.
     *
     * If async_recv_wait resolves with NABTO_EC_OK, the recv_from
     * function is guaranteed to be called. If async recv_wait
     * resolves with something else than NABTO_EC_OK the socket is
     * assumed to be closed for further reading.
     */
    void (*async_recv_wait)(np_udp_socket* socket, struct np_event_ec* completionEvent);

    /**
     * Recv an UDP packet from a socket.
     *
     * @return NABTO_EC_OK iff a packet was ready and put into the recv buffer.
     *         NABTO_EC_AGAIN if the socket does not have ready data or the retrieval would have blocked.
     *         NABTO_EC_EOF if no more data can be received from the socket.
     */
    np_error_code (*recv_from)(np_udp_socket* socket, struct np_udp_endpoint* ep, uint8_t** buffer, size_t bufferSize, size_t* recvSize);

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
