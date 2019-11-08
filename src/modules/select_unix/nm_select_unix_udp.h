#ifndef _NM_SELECT_UNIX_UDP_H_
#define _NM_SELECT_UNIX_UDP_H_

#include "nm_select_unix.h"

#include <platform/np_platform.h>

#ifdef __cplusplus
extern "C" {
#endif

np_error_code nm_select_unix_udp_init(struct nm_select_unix* ctx, struct np_platform *pl);
void nm_select_unix_udp_deinit(struct nm_select_unix* ctx);
void nm_select_unix_udp_build_fd_sets(struct nm_select_unix* ctx, struct nm_select_unix_udp_sockets* sockets);
void nm_select_unix_udp_handle_select(struct nm_select_unix* ctx, int nfds);
bool nm_select_unix_udp_has_sockets(struct nm_select_unix* ctx);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
