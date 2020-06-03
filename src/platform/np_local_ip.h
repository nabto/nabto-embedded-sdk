#ifndef _NP_SYSTEM_INFORMATION_H_
#define _NP_SYSTEM_INFORMATION_H_

struct np_local_ip_functions;

struct np_local_ip {
    const struct np_local_ip_functions* vptr;
    void* data;
};


struct np_local_ip_functions {
    /**
     * Get the local IP address.
     *
     * @param data      Pointer to opaque data
     * @param addrs     Pointer to an ip_address array of size addrsSize
     * @param addrsSize size of addrs
     * @return number of ip addresses put into the array
     */
    size_t (*get_local_ips)(void* data,  struct np_ip_address *addrs, size_t addrsSize);
};

#endif
