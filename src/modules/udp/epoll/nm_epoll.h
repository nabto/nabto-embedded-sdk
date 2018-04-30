#ifndef _NABTO_UDP_EPOLL_MODULE_H_
#define _NABTO_UDP_EPOLL_MODULE_H_

#include <platform/udp.h>

/*
 * initialize the epoll module in a nabto_platform context This call
 * will add the epoll module functions to the udp module in the
 * nabto_platform The platform is also used internally in the epoll
 * module, and must therefore be kept alive from the call of this
 * function until the module is no longer needed.
 */
void nm_epoll_init(nabto_platform *pl_in);

/*
 * async functions implementing epoll functionallity for the udp
 * interface of <platform/udp.h> used in the nabto_platform.
 */
void nm_epoll_async_create(nabto_udp_socket_created_callback cb, void* data);
void nm_epoll_async_bind_port(uint16_t port, nabto_udp_socket_created_callback cb, void* data);
void nm_epoll_async_send_to(nabto_udp_socket* socket, struct nabto_udp_endpoint* ep,
                            uint8_t* buffer, uint16_t bufferSize, nabto_udp_packet_sent_callback cb, void* data);
void nm_epoll_async_recv_from(nabto_udp_socket* socket, nabto_udp_packet_received_callback cb, void* data);
void nm_epoll_async_destroy(nabto_udp_socket* socket, nabto_udp_socket_destroyed_callback cb, void* data);

#endif // _NABTO_UDP_EPOLL_MODULE_H_
