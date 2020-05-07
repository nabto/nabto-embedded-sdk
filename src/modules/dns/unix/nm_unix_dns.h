#ifndef _NP_UNIX_DNS_H_
#define _NP_UNIX_DNS_H_

#include <platform/np_platform.h>
#include <platform/np_dns.h>
#include <nabto_types.h>

#ifdef __cplusplus
extern "C" {
#endif

void nm_unix_dns_init(struct np_platform* pl);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // _NP_UNIX_DNS_H_
