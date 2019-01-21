#ifndef _NP_WIN_DNS_H_
#define _NP_WIN_DNS_H_

#include <platform/np_dns.h>
#include <nabto_types.h>

struct np_platform;

void nm_win_dns_init(struct np_platform* pl);
np_error_code nm_win_dns_resolve(struct  np_platform* pl, const char* host, np_dns_resolve_callback cb, void* data);

#endif // _NP_WIN_DNS_H_
