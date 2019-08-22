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

void nm_epoll_udp_init(struct nm_epoll_context* epoll, struct np_platform* pl);

void nm_epoll_udp_handle_event(np_udp_socket* sock, uint32_t events);


#endif // _NP_UDP_EPOLL_MODULE_H_
