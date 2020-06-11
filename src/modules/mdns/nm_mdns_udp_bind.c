
#include "nm_mdns_udp_bind.h"

void nm_mdns_udp_bind_async_ipv4(struct nm_mdns_udp_bind* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    return udp->vptr->async_bind_mdns_ipv4(sock, completionEvent);
}

void nm_mdns_udp_bind_async_ipv6(struct nm_mdns_udp_bind* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    return udp->vptr->async_bind_mdns_ipv6(sock, completionEvent);
}
