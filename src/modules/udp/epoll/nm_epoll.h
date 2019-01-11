#ifndef NM_UDP_EPOLL_MODULE_H
#define NM_UDP_EPOLL_MODULE_H

#include <nabto_types.h>
#include <platform/np_udp.h>
#include <platform/np_platform.h>
#include <sys/epoll.h>


/**
 * initialize the epoll module in a np_platform context This call
 * will add the epoll module functions to the udp module in the
 * np_platform The platform is also used internally in the epoll
 * module, and must therefore be kept alive from the call of this
 * function until the module is no longer needed.
 */
void nm_epoll_init(struct np_platform *pl_in);

void nm_epoll_close(struct np_platform* pl);

int nm_epoll_timed_wait(uint32_t ms);
int nm_epoll_inf_wait();

void nm_epoll_read(int nfds);

/**
 * async functions implementing epoll functionallity for the udp
 * interface of <platform/udp.h> used in the np_platform.
 * Defined in .h file for testing purposes
 */
void nm_epoll_async_create(np_udp_socket_created_callback cb, void* data);
void nm_epoll_async_bind_port(uint16_t port, np_udp_socket_created_callback cb, void* data);
void nm_epoll_async_send_to(struct np_udp_send_context* ctx);
void nm_epoll_async_recv_from(np_udp_socket* socket,
                              np_udp_packet_received_callback cb, void* data);
enum np_ip_address_type nm_epoll_get_protocol(np_udp_socket* socket);
uint16_t nm_epoll_get_local_port(np_udp_socket* socket);
void nm_epoll_async_destroy(np_udp_socket* socket, np_udp_socket_destroyed_callback cb, void* data);



#endif // _NP_UDP_EPOLL_MODULE_H_
