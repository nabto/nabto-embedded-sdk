#ifndef _NP_UNIX_DNS_H_
#define _NP_UNIX_DNS_H_

#include <platform/np_platform.h>
#include <platform/np_dns.h>
#include <nabto_types.h>

void nm_unix_dns_init(struct np_platform* pl);

np_error_code nm_unix_dns_resolve(struct  np_platform* pl, const char* host, np_dns_resolve_callback cb, void* data);

#endif // _NP_UNIX_DNS_H_
