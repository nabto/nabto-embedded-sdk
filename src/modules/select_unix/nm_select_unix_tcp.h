#ifndef _NM_SELECT_UNIX_TCP_H_
#define _NM_SELECT_UNIX_TCP_H_

#include "nm_select_unix.h"

#ifdef __cplusplus
extern "C" {
#endif

void nm_select_unix_tcp_build_fd_sets(struct nm_select_unix* ctx);
void nm_select_unix_tcp_handle_select(struct nm_select_unix* ctx, int nfds);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
