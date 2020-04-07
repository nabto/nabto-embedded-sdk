#include "nm_posix_udp.h"

#include <platform/np_error_code.h>
#include <platform/np_logging.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define LOG NABTO_LOG_MODULE_UDP

np_error_code nm_posix_udp_send_to(struct nm_posix_udp_socket* s, const struct np_udp_endpoint* ep, const uint8_t* buffer, uint16_t bufferSize)
{
    ssize_t res;

    struct np_ip_address sendIp;

    if (s->type == ep->ip.type) {
        // No conversion needed.
        sendIp = ep->ip;
    } else if (s->type == NABTO_IPV6 && ep->ip.type == NABTO_IPV4) {
        // convert ipv4 to ipv6 mapped ipv4
        np_ip_convert_v4_to_v4_mapped(&ep->ip, &sendIp);
    } else if (s->type == NABTO_IPV4 && np_ip_is_v4_mapped(&ep->ip)) {
        np_ip_convert_v4_mapped_to_v4(&ep->ip, &sendIp);
    } else {
        NABTO_LOG_TRACE(LOG, "Cannot send ipv6 packets on an ipv4 socket.");
        return NABTO_EC_FAILED_TO_SEND_PACKET;
    }

    if (sendIp.type == NABTO_IPV4) {
        struct sockaddr_in srv_addr;
        srv_addr.sin_family = AF_INET;
        srv_addr.sin_port = htons (ep->port);
        memcpy((void*)&srv_addr.sin_addr, sendIp.ip.v4, sizeof(srv_addr.sin_addr));
        res = sendto (s->sock, buffer, bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    } else { // IPv6
        struct sockaddr_in6 srv_addr;
        srv_addr.sin6_family = AF_INET6;
        srv_addr.sin6_flowinfo = 0;
        srv_addr.sin6_scope_id = 0;
        srv_addr.sin6_port = htons (ep->port);
        memcpy((void*)&srv_addr.sin6_addr,sendIp.ip.v6, sizeof(srv_addr.sin6_addr));
        res = sendto (s->sock, buffer, bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    }

    if (res < 0) {
        int status = errno;
        NABTO_LOG_TRACE(LOG, "UDP returned error status %i", status);
        if (status == EAGAIN || status == EWOULDBLOCK) {
            // expected
            // just drop the packet and the upper layers will take care of retransmissions.
        } else {

            if (status == EADDRNOTAVAIL || // if we send to ipv6 scopes we do not have
                status == ENETUNREACH || // if we send ipv6 on a system without it.
                status == EAFNOSUPPORT) // if we send ipv6 on an ipv4 only socket
            {
                NABTO_LOG_TRACE(LOG,"ERROR: (%i) '%s' in nm_epoll_event_send_to", (int) status, strerror(status));
            } else {
                NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_epoll_event_send_to", (int) status, strerror(status));
            }
            return NABTO_EC_FAILED_TO_SEND_PACKET;
        }
    }
    NABTO_LOG_TRACE(LOG, "Send packet of size %d, to %s", bufferSize, np_ip_address_to_string(&sendIp));

    return NABTO_EC_OK;
}


np_error_code nm_posix_bind_port(struct nm_posix_udp_socket* s, uint16_t port)
{
    int status;

    if (s->type == NABTO_IPV6) {
        struct sockaddr_in6 si_me6;
        memset(&si_me6, 0, sizeof(si_me6));
        si_me6.sin6_family = AF_INET6;
        si_me6.sin6_port = htons(port);
        si_me6.sin6_addr = in6addr_any;
        status = bind(s->sock, (struct sockaddr*)&si_me6, sizeof(si_me6));
    } else {
        struct sockaddr_in si_me;
        memset(&si_me, 0, sizeof(si_me));
        si_me.sin_family = AF_INET;
        si_me.sin_port = htons(port);
        si_me.sin_addr.s_addr = INADDR_ANY;
        status = bind(s->sock, (struct sockaddr*)&si_me, sizeof(si_me));
    }

    NABTO_LOG_TRACE(LOG, "bind returned %i", status);

    if (status == 0) {
        return NABTO_EC_OK;
    } else {
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }
}

np_error_code nm_posix_udp_create_socket_any(struct nm_posix_udp_socket* s)
{
    int sock = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock == -1) {
        sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (s->sock == -1) {
            NABTO_LOG_ERROR(LOG, "Unable to create socket: (%i) '%s'.", errno, strerror(errno));
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        } else {
            NABTO_LOG_WARN(LOG, "IPv4 socket opened since IPv6 socket creation failed");
            s->type = NABTO_IPV4;
        }
    } else {
        int no = 0;
        s->type = NABTO_IPV6;
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no)))
        {
            NABTO_LOG_ERROR(LOG,"Unable to set option: (%i) '%s'.", errno, strerror(errno));

            close(s->sock);
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        }
    }
    s->sock = sock;
    return NABTO_EC_OK;
}

np_error_code nm_posix_udp_create_socket_ipv6(struct nm_posix_udp_socket* s)
{
    int sock = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock == -1) {
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }
    s->type = NABTO_IPV6;
    s->sock = sock;
    return NABTO_EC_OK;
}

np_error_code nm_posix_udp_create_socket_ipv4(struct nm_posix_udp_socket* s)
{
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock == -1) {
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }
    s->type = NABTO_IPV4;
    s->sock = sock;
    return NABTO_EC_OK;
}
