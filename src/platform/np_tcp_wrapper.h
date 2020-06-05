#ifndef _NP_TCP_WRAPPER_H_
#define _NP_TCP_WRAPPER_H_

#include "interfaces/np_tcp.h"

/**
 * TCP wrapper functions see np_tcp for help
 */

#ifdef __cplusplus
extern "C" {
#endif

np_error_code np_tcp_create(struct np_tcp* obj, struct np_tcp_socket** sock);
void np_tcp_destroy(struct np_tcp* obj, struct np_tcp_socket* sock);
void np_tcp_async_connect(struct np_tcp* obj, struct np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, struct np_completion_event* completionEvent);
void np_tcp_async_write(struct np_tcp* obj, struct np_tcp_socket* sock, const void* data, size_t dataLength, struct np_completion_event* completionEvent);
void np_tcp_async_read(struct np_tcp* obj, struct np_tcp_socket* sock, void* buffer, size_t bufferLength, size_t* readLength, struct np_completion_event* completionEvent);
void np_tcp_shutdown(struct np_tcp* obj, struct np_tcp_socket* sock);
void np_tcp_abort(struct np_tcp* obj, struct np_tcp_socket* sock);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
