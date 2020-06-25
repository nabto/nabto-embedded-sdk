#ifndef _NP_SYSTEM_INFORMATION_H_
#define _NP_SYSTEM_INFORMATION_H_

#include <stddef.h>
#include <platform/np_ip_address.h>

struct np_local_ip_functions;

// A local ip interface. The purpose for this interface is to allow
// the system to query for local ip addresses on the system.


struct np_local_ip {
    // Pointer to a struct defining the local ip function.
    const struct np_local_ip_functions* mptr;
    // Pointer to implementation specific data.
    void* data;
};


struct np_local_ip_functions {
    /**
     * Get the local IP address.
     *
     * @param obj       The local ip object.
     * @param addrs     Pointer to an ip_address array of size addrsSize.
     * @param addrsSize size of addrs.
     * @return number of ip addresses put into the array.
     */
    size_t (*get_local_ips)(struct np_local_ip* obj,  struct np_ip_address *addrs, size_t addrsSize);
};

#endif
