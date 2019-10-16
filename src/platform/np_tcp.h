#ifndef _NP_TCP_H_
#define _NP_TCP_H_

#include <platform/np_ip_address.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;

typedef void (*np_tcp_write_callback)(np_error_code ec, void* userData);
typedef void (*np_tcp_read_callback)(np_error_code ec, size_t readen, void* userData);
typedef void (*np_tcp_connect_callback)(np_error_code ec, void* userData);

typedef struct np_tcp_socket np_tcp_socket;

struct np_tcp_module {
    /**
     * Create a tcp socket.
     */
    np_error_code (*create)(struct np_platform* pl, np_tcp_socket** sock);
    void (*destroy)(np_tcp_socket* sock);

    np_error_code (*async_connect)(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, np_tcp_connect_callback cb, void* userData);


    np_error_code (*async_write)(np_tcp_socket* sock, const void* data, size_t dataLength, np_tcp_write_callback cb, void* userData);
    np_error_code (*async_read)(np_tcp_socket* sock, void* buffer, size_t bufferLength, np_tcp_read_callback cb, void* userData);

    /**
     * Shutdown further write to the socket.
     */
    np_error_code (*shutdown)(np_tcp_socket* sock);

    /**
     * abort outstanding async operations on the socket, no further
     * reads or writes are possible.
     */
    np_error_code (*abort)(np_tcp_socket* sock);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
