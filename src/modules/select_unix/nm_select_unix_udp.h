#ifndef _NM_SELECT_UNIX_UDP_H_
#define _NM_SELECT_UNIX_UDP_H_

#include "nm_select_unix.h"

#include <platform/np_platform.h>

#ifdef __cplusplus
extern "C" {
#endif

void nm_select_unix_udp_build_fd_sets(struct nm_select_unix* ctx);
void nm_select_unix_udp_handle_select(struct nm_select_unix* ctx, int nfds);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
