#ifndef _NP_UDP_WRAPPER_H_
#define _NP_UDP_WRAPPER_H_

#include "interfaces/np_udp.h"

// Wrapper functions for the functionality. See above struct for documentation for the functions.
np_error_code np_udp_create(struct np_udp* udp, struct np_udp_socket** sock);

void np_udp_destroy(struct np_udp* udp, struct np_udp_socket* sock);

void np_udp_abort(struct np_udp* udp, struct np_udp_socket* sock);

void np_udp_async_bind_port(struct np_udp* udp, struct np_udp_socket* sock, uint16_t port, struct np_completion_event* completionEvent);

void np_udp_async_bind_mdns_ipv4(struct np_udp* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent);

void np_udp_async_bind_mdns_ipv6(struct np_udp* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent);

void np_udp_async_send_to(struct np_udp* udp,
                          struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                          uint8_t* buffer, uint16_t bufferSize,
                          struct np_completion_event* completionEvent);

void np_udp_async_recv_wait(struct np_udp* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent);

np_error_code np_udp_recv_from(struct np_udp* udp, struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* recvSize);


uint16_t np_udp_get_local_port(struct np_udp* udp, struct np_udp_socket* sock);

#endif
