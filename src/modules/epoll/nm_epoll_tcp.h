#ifndef _NM_EPOLL_TCP_H_
#define _NM_EPOLL_TCP_H_

#include "nm_epoll.h"
#include <platform/np_platform.h>

void nm_epoll_tcp_init(struct nm_epoll_context* epoll, struct np_platform* pl);

void nm_epoll_tcp_handle_event(np_tcp_socket* sock, uint32_t events);

void nm_epoll_tcp_resolve_close(struct nm_epoll_base* base);
#endif
