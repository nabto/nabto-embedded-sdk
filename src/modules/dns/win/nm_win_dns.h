#ifndef _NM_WIN_DNS_H_
#define _NM_WIN_DNS_H_

#include <platform/np_dns.h>
#include <nabto_types.h>

struct np_platform;

np_error_code nm_win_dns_resolve(struct  np_platform* pl, const char* host, np_dns_resolve_callback cb, void* data);

#endif // _NP_WIN_DNS_H_
