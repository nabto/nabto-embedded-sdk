#ifndef _NP_LOCAL_IP_H_
#define _NP_LOCAL_IP_H_

struct np_local_ip {
    /**
     * Get the local IP address.
     *
     * @param addrs     Pointer to an ip_address array of size addrsSize
     * @param addrsSize size of addrs
     * @return number of ip addresses put into the array
     */
    size_t (*get_local_ip)( struct np_ip_address *addrs, size_t addrsSize);
};

#endif
