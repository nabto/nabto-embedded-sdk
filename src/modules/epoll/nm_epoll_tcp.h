#ifndef _NM_TCP_EPOLL_H_
#define _NM_TCP_EPOLL_H_

#include "nm_epoll.h"
#include <platform/np_platform.h>

void nm_tcp_epoll_init(struct nm_epoll_context* epoll, struct np_platform* pl);

#endif
