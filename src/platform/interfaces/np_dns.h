#ifndef _NP_DNS_H_
#define _NP_DNS_H_

#ifndef NP_DNS_RESOLVED_IPS_MAX
#define NP_DNS_RESOLVED_IPS_MAX 4
#endif

#include <platform/np_error_code.h>
#include <platform/np_ip_address.h>
#include <platform/np_types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_completion_event;
struct np_dns_functions;

struct np_dns {
    const struct np_dns_functions* mptr;
    // Pointer to implementation specific data.
    void* data;
};

struct np_dns_functions {
    /**
     * Resolve ipv4 addresses for the host name.
     *
     * The completion event shall be resolved when the dns resolution
     * has either failed or succeeded.
     *
     * @param obj  Dns implemetation object.
     * @param host  The host to resolve.
     * @param ips  The array to store the resolved ips in.
     * @param ipsSize  The size of the ips array.
     * @param ipsResolved  The number of ips put in the the ips array.
     * @param completionEvent  The completion event.
     */
    void (*async_resolve_v4)(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

    /**
     * Resolve ipv6 addresses for the host name.
     *
     * The completion event shall be resolved when the dns resolution
     * has either failed or succeeded.
     *
     * @param obj  Dns implementation object.
     * @param host  The host to resolve.
     * @param ips  The array to store the resolved ips in.
     * @param ipsSize  The size of the ips array.
     * @param ipsResolved  The number of ips put in the the ips array.
     * @param completionEvent  The completion event.
     */
    void (*async_resolve_v6)(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

};

#ifdef __cplusplus
} //extern "C"
#endif

#endif //_NP_DNS_H_
