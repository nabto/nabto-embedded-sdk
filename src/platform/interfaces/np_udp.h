#ifndef NP_UDP_H
#define NP_UDP_H

#include <platform/np_ip_address.h>
#include <platform/np_error_code.h>
#include <platform/np_communication_buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_completion_event;
struct np_udp_socket;
struct np_udp_impl;

struct np_udp_endpoint {
    struct np_ip_address ip;
    uint16_t port;
};

struct np_udp {
    const struct np_udp_functions* mptr;
    // Pointer to data which is implementation specific.
    void* data;
};

/**
 * This struct defines a list of functions which is required for udp
 * communication.
 *
 * Each function needs to point to a specific platform dependent
 * implementation.
 */
struct np_udp_functions {
    /**
     * create an UDP socket resource. If create returns NABTO_EC_OK,
     * destroy must be called when socket is no longer in use to clean
     * up the resource.
     *
     * The udpModule pointer is a reference to the implementation of
     * the udp module.
     *
     * @param obj  A pointer to the actual udp object.
     * @param sock  The created socket.
     * @return NABTO_EC_OK iff the socket resource was created.
     */
    np_error_code (*create)(struct np_udp* obj, struct np_udp_socket** sock);

    /**
     * Destroy a socket. This will close everything and clean up
     * resources. All outstanding completion events will be resolved
     * with NABTO_EC_ABORTED.
     *
     * @param sock  The socket resource
     */
    void (*destroy)(struct np_udp_socket* sock);

    /**
     * Abort outstanding async operations on the socket resolving all
     * outstanding completion events. No further reads or writes are
     * possible.  The socket can be destroyed imediately after abort
     * or it can be destroyed when all completion events has been
     * resolved.
     *
     * @param sock  The socket resource.
     */
    void (*abort)(struct np_udp_socket* sock);

    /**
     * Bind a socket to a port. Port 0 means ephemeral.
     *
     * The socket should most likely be created as an dualmode
     * ipv4+ipv6 socket.
     *
     * The completion event is resolved with NABTO_EC_OK if the socket
     * is bound to the specified port and ready to be used. if the
     * function fails the completion event shall be resolved with an
     * error.
     *
     * @param sock  The socket resource;
     * @param port  The port to bind to, 0 means ephemeral port.
     * @param completionEvent  The event to be resolved when the socket is bound and ready to be used.
     *
     */
    void (*async_bind_port)(struct np_udp_socket* sock, uint16_t port, struct np_completion_event* completionEvent);

    /**
     * Send packet async. It's the responsibility of the caller to
     * keep the ep and buffer alive until the completion event is
     * resolved.
     *
     * The completion event shall be resolved when a result of the
     * operation is available.
     *
     * @param sock  The socket resource.
     * @param ep  The endpoint. If the send to is deferred the endpoint has to be copied.
     * @param buffer  The buffer for data which us to be sent. The caller
     *                keeps the buffer alive until the completion event is resolved unless
     *                abort or destroy has been called.
     * @param bufferSize  The size of the buffer.
     * @param completionEvent  The completion event, which is resolved when the
     */
    void (*async_send_to)(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                          uint8_t* buffer, uint16_t bufferSize,
                          struct np_completion_event* completionEvent);

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
     *
     * The completion event shall be resolved when a result of the
     * operation is available.
     *
     * @param sock  The socket resource
     * @param completionEvent  The completion event to be resolved
     *                         when data is ready to be received from the socket.
     */
    void (*async_recv_wait)(struct np_udp_socket* sock, struct np_completion_event* completionEvent);

    /**
     * Recv an UDP packet from a socket.
     *
     * If the provided buffer is smaller than the received packet, copy as much
     * of the packet into the buffer and discard the rest.
     *
     * @param sock  The socket resource
     * @param ep  The endpoint where the packet came from.
     * @param buffer  The destination buffer.
     * @param bufferSize  The destination buffer size.
     * @param recvSize    The actual amount of data received.
     * @return NABTO_EC_OK iff a packet was ready and put into the recv buffer.
     *         NABTO_EC_AGAIN if the socket does not have ready data or the
     *         retrieval would have blocked. NABTO_EC_EOF if no more data can be
     *         received from the socket.
     */
    np_error_code (*recv_from)(struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* recvSize);

    /**
     * Get the local port number
     *
     * @param sock  The socket resource
     * @return  The port number the socket is bound to.
     */
    uint16_t (*get_local_port)(struct np_udp_socket* sock);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
