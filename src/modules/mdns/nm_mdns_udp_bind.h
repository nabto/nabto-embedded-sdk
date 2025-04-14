#ifndef _NM_MDNS_UDP_BIND_H_
#define _NM_MDNS_UDP_BIND_H_



/**
 * This defines the udp bind functions which is needed by the mdns server.
 */

struct nm_mdns_udp_bind_functions;
struct np_udp_socket;
struct np_completion_event;

struct nm_mdns_udp_bind {
    struct nm_mdns_udp_bind_functions* mptr;
    void* data;
};

struct nm_mdns_udp_bind_functions {
    /**
     * Optional function to bind a socket the mdns port and ipv4 mdns
     * multicast group.  The socket is bound to 5353 and needs to have
     * the equivalent of the REUSEPORT flag set. The socket needs to
     * join the ipv4 multicast group 224.0.0.251.
     *
     * The completion event shall be resolved when a result for the
     * operation is available.
     *
     * If the function is not implemented properly it needs to resolve
     * the completion event with NABTO_EC_NOT_IMPLEMENTED.
     *
     * @param sock  The socket resource.
     * @param completionEvent  The completion event to be resolved the socket is bound.
     */
    void (*async_bind_mdns_ipv4)(struct np_udp_socket* sock, struct np_completion_event* completionEvent);

    /**
     * Optional function to bind a socket the mdns port and ipv6 mdns
     * multicast group.  The socket is bound to 5353 and needs to have
     * the equivalent of the REUSEPORT flag set. The socket needs to
     * join the ipv6 multicast group ff02::fb.
     *
     * The completion event shall be resolved when a result for the
     * operation is available.
     *
     * If the function is not implemented properly it needs to resolve
     * the completion event with NABTO_EC_NOT_IMPLEMENTED.
     *
     * @param sock  The socket resource.
     * @param completionEvent  The completion event to be resolved the socket is bound.
     */
    void (*async_bind_mdns_ipv6)(struct np_udp_socket* sock, struct np_completion_event* completionEvent);
};


// see above struct for documentation.
void nm_mdns_udp_bind_async_ipv4(struct nm_mdns_udp_bind* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent);

void nm_mdns_udp_bind_async_ipv6(struct nm_mdns_udp_bind* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent);


#endif
