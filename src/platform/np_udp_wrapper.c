#include "np_udp_wrapper.h"

// Wrapper functions for the functionality. See above struct for documentation for the functions.
np_error_code np_udp_create(struct np_udp* udp, struct np_udp_socket** sock)
{
    return udp->vptr->create(udp, sock);
}

void np_udp_destroy(struct np_udp* udp, struct np_udp_socket* sock)
{
    return udp->vptr->destroy(sock);
}

void np_udp_abort(struct np_udp* udp, struct np_udp_socket* sock)
{
    return udp->vptr->abort(sock);
}

void np_udp_async_bind_port(struct np_udp* udp, struct np_udp_socket* sock, uint16_t port, struct np_completion_event* completionEvent)
{
    return udp->vptr->async_bind_port(sock, port, completionEvent);
}

void np_udp_async_bind_mdns_ipv4(struct np_udp* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    return udp->vptr->async_bind_mdns_ipv4(sock, completionEvent);
}

void np_udp_async_bind_mdns_ipv6(struct np_udp* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    return udp->vptr->async_bind_mdns_ipv6(sock, completionEvent);
}

void np_udp_async_send_to(struct np_udp* udp,
                                 struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                 uint8_t* buffer, uint16_t bufferSize,
                                 struct np_completion_event* completionEvent)
{
    return udp->vptr->async_send_to(sock, ep, buffer, bufferSize, completionEvent);
}

void np_udp_async_recv_wait(struct np_udp* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    return udp->vptr->async_recv_wait(sock, completionEvent);
}

np_error_code np_udp_recv_from(struct np_udp* udp, struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* recvSize)
{
    return udp->vptr->recv_from(sock, ep, buffer, bufferSize, recvSize);
}


uint16_t np_udp_get_local_port(struct np_udp* udp, struct np_udp_socket* sock)
{
    return udp->vptr->get_local_port(sock);
}
