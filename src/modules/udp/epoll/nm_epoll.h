#ifndef NM_UDP_EPOLL_MODULE_H
#define NM_UDP_EPOLL_MODULE_H

#include <nabto_types.h>
#include <platform/np_client_connect.h>
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

/**
 * Handles events from epoll_wait
 */
void nm_epoll_handle_event(np_udp_socket* sock); // consider an np_epoll_event type instead of reusing the socket structure

void nm_epoll_wait();

/**
 * async functions implementing epoll functionallity for the udp
 * interface of <platform/udp.h> used in the np_platform.
 */
void nm_epoll_async_create(np_udp_socket_created_callback cb, void* data);
void nm_epoll_async_bind_port(uint16_t port, np_udp_socket_created_callback cb, void* data);
void nm_epoll_async_send_to(np_udp_socket* socket, struct np_udp_endpoint* ep,
                            np_communication_buffer* buffer, uint16_t bufferSize, np_udp_packet_sent_callback cb, void* data);
void nm_epoll_async_recv_from(np_udp_socket* socket, enum np_channel_type type, np_udp_packet_received_callback cb, void* data);
enum np_ip_address_type nm_epoll_get_protocol(np_udp_socket* socket);
void nm_epoll_async_destroy(np_udp_socket* socket, np_udp_socket_destroyed_callback cb, void* data);

#endif // _NP_UDP_EPOLL_MODULE_H_
