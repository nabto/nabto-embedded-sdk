#ifndef _NM_POSIX_UDP_H_
#define _NM_POSIX_UDP_H_

#include <platform/np_udp.h>

typedef int nm_posix_socket;

struct nm_posix_received_ctx {
    np_udp_packet_received_callback cb;
    void* data;
    struct np_event event;
};

struct nm_posix_udp_socket {
    nm_posix_socket sock;
    struct nm_posix_received_ctx recv;
    enum np_ip_address_type type;
};

np_error_code nm_posix_udp_send_to(struct nm_posix_udp_socket* s, const struct np_udp_endpoint* ep, const uint8_t* buffer, uint16_t bufferSize);

np_error_code nm_posix_bind_port(struct nm_posix_udp_socket* s, uint16_t port);

np_error_code nm_posix_udp_create_socket_any(struct nm_posix_udp_socket* s);
np_error_code nm_posix_udp_create_socket_ipv6(struct nm_posix_udp_socket* s);
np_error_code nm_posix_udp_create_socket_ipv4(struct nm_posix_udp_socket* s);


#endif
