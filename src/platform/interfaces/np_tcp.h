#ifndef _NP_TCP_H_
#define _NP_TCP_H_

#include <platform/np_ip_address.h>
#include <platform/np_error_code.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_completion_event;

/**
 * opaque pointer which should be defined by the implementor.
 */
struct np_tcp_socket;

struct np_tcp_functions;


struct np_tcp {
    const struct np_tcp_functions* mptr;
    // Pointer to data which is implementation specific
    void* data;
};

struct np_tcp_functions {
    /**
     * Create a tcp socket.
     *
     * @param obj  The TCP object.
     * @param sock  The resulting socket resource.
     * @return NABTO_EC_OK iff the socket resource was created.
     */
    np_error_code (*create)(struct np_tcp* obj, struct np_tcp_socket** sock);

    /**
     * Destroy a socket. All outstanding completion events will be
     * resolved.
     *
     * @param sock  The socket resource.
     */
    void (*destroy)(struct np_tcp_socket* sock);

    /**
     * Connect a socket to the given addresa and port.
     *
     * The completion event shall be resolved when a result of the
     * operation is available.
     *
     * Completion event error codes:
     *   NABTO_EC_OK: Connected ok.
     *   NABTO_EC_ABORTED: If the socket could not be connected to the destination.
     *
     * @param sock  The socket resource.
     * @param address  The address to connect to.
     * @param port  The port to connect to.
     * @param completionEvent  The completion event.
     */
    void (*async_connect)(struct np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, struct np_completion_event* completionEvent);

    /**
     * Write data to the tcp socket.
     *
     * The completion event shall be resolved when a result of the
     * operation is available.
     *
     * Completion event error codes:
     *   * NABTO_EC_OK: if the data was written to the tcp socket.
     *   * NABTO_EC_ABORTED: If the socket has been closed by the application.
     *   * NABTO_EC_*: if an unrecoverable error occured.
     *
     * @param sock  The socket resource.
     * @param data  The data to write.
     * @param dataLength  The length of the data to write.
     * @param completionEvent  The event to call when data has been written or the write failed.
     */
    void (*async_write)(struct np_tcp_socket* sock, const void* data, size_t dataLength, struct np_completion_event* completionEvent);

    /**
     * Read data from a socket.
     *
     * The completion event shall be resolved when a result of the
     * operation is available.
     *
     * Completion event error codes:
     *   * NABTO_EC_OK: if the read was successful.
     *   * NABTO_EC_EOF: id the socket has been closed properly by the other end and no more data is available to be read.
     *   * NABTO_EC_ABORTED: if the socket has been closed by the application.
     *   * NABTO_EC_*: if an unrecoverable error occurs.
     *
     * @param sock  The socket resource.
     * @param buffer  The buffer to write data to.
     * @param bufferLength  The length of the buffer.
     * @param readLength  The length of received data.
     * @param completionEvent  The completion event to resolve when data has been read.
     */
    void (*async_read)(struct np_tcp_socket* sock, void* buffer, size_t bufferLength, size_t* readLength, struct np_completion_event* completionEvent);

    /**
     * Shutdown further write to the socket.
     *
     * This equals shutdown(sock, SHUT_WR)
     *
     * @param sock  The socket resource to shutdown.
     */
    void (*shutdown)(struct np_tcp_socket* sock);

    /**
     * Abort outstanding async operations on the socket, no further
     * reads or writes are possible. This operation is idempotent and
     * hence can be called multiple times.
     *
     * @param sock  The socket resource.
     */
    void (*abort)(struct np_tcp_socket* sock);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
