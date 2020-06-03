#ifndef _NM_LIBEVENT_DNS_H_
#define _NM_LIBEVENT_DNS_H_

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct event_base;

const struct np_dns_functions* nm_libevent_dns_functions();

#ifdef __cplusplus
} //extern "C"
#endif

#endif
