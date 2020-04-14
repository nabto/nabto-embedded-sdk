#include "nm_posix_udp.h"
#include "nm_posix_types.h"

#include <platform/np_error_code.h>
#include <platform/np_logging.h>
#include <platform/np_platform.h>
#include <platform/np_communication_buffer.h>

#include <sys/types.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <errno.h>
#include <string.h>


#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#include <ws2ipdef.h>
#endif


#ifdef HAVE_UNISTD_H
// close on unix
#include <unistd.h>
#endif

#ifdef HAVE_IO_H
// close on windows
#include <io.h>
#endif

#include <fcntl.h>




#define LOG NABTO_LOG_MODULE_UDP

nm_posix_socket nonblocking_socket(int domain, int type)
{
#if defined(SOCK_NONBLOCK)
    return socket(domain, type | SOCK_NONBLOCK, 0);
#endif

#ifdef F_GETFL
    int sock = socket(domain, type, 0);

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) flags = 0;
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    return sock;
#endif
}

np_error_code nm_posix_udp_send_to(struct nm_posix_udp_socket* s, const struct np_udp_endpoint* ep, const uint8_t* buffer, uint16_t bufferSize)
{
    ssize_type res;

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

    NABTO_LOG_TRACE(LOG, "Sending packet of size %d, to %s:%d", bufferSize, np_ip_address_to_string(&sendIp), ep->port);
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

    return NABTO_EC_OK;
}

void nm_posix_udp_event_try_recv_from(void* userData)
{
    struct nm_posix_udp_socket* sock = userData;
    if (sock->recv.cb == NULL) {
        // ignore data if no recv callback is registered
        return;
    }
    struct np_udp_endpoint ep;
    struct np_platform* pl = sock->pl;
    ssize_type recvLength;
    uint8_t* start;
    start = pl->buf.start(sock->recvBuffer);
    if (sock->type == NABTO_IPV6) {
        struct sockaddr_in6 sa;
        socklen_type addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, start,  pl->buf.size(sock->recvBuffer), 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.ip.v6, &sa.sin6_addr.s6_addr, sizeof(ep.ip.ip.v6));
        ep.port = ntohs(sa.sin6_port);
        ep.ip.type = NABTO_IPV6;
    } else {
        struct sockaddr_in sa;
        socklen_type addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, start, pl->buf.size(sock->recvBuffer), 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.ip.v4, &sa.sin_addr.s_addr, sizeof(ep.ip.ip.v4));
        ep.port = ntohs(sa.sin_port);
        ep.ip.type = NABTO_IPV4;
    }
    if (recvLength < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK) {
            // expected
            // wait for next event to check for data.
            return;
        } else {
            np_udp_packet_received_callback cb;
            NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_posix_event_try_read", strerror(status), (int) status);
            if(sock->recv.cb) {
                cb = sock->recv.cb;
                sock->recv.cb = NULL;
                cb(NABTO_EC_UDP_SOCKET_ERROR, ep, NULL, 0, sock->recv.data);
            }
            return;
        }
    }
    if (sock->recv.cb) {
        np_udp_packet_received_callback cb = sock->recv.cb;
        sock->recv.cb = NULL;
        cb(NABTO_EC_OK, ep, pl->buf.start(sock->recvBuffer), recvLength, sock->recv.data);
    }
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

uint16_t nm_posix_udp_get_local_port(struct nm_posix_udp_socket* s)
{
    if (s->type == NABTO_IPV6) {
        struct sockaddr_in6 addr;
        addr.sin6_port = 0;
        socklen_type length = sizeof(struct sockaddr_in6);
        getsockname(s->sock, (struct sockaddr*)(&addr), &length);
        return htons(addr.sin6_port);
    } else {
        struct sockaddr_in addr;
        addr.sin_port = 0;
        socklen_type length = sizeof(struct sockaddr_in);
        getsockname(s->sock, (struct sockaddr*)(&addr), &length);
        return htons(addr.sin_port);
    }
}

np_error_code nm_posix_udp_create_socket_any(struct nm_posix_udp_socket* s)
{
    int sock = nonblocking_socket(AF_INET6, SOCK_DGRAM);
    if (sock == -1) {
        sock = nonblocking_socket(AF_INET, SOCK_DGRAM);
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
    int sock = nonblocking_socket(AF_INET6, SOCK_DGRAM);
    if (sock == -1) {
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    int no = 0;
    int status = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no));
    if (status < 0) {
        NABTO_LOG_ERROR(LOG, "Cannot set IPV6_V6ONLY");
    }

    s->type = NABTO_IPV6;
    s->sock = sock;
    return NABTO_EC_OK;
}

np_error_code nm_posix_udp_create_socket_ipv4(struct nm_posix_udp_socket* s)
{
    int sock = nonblocking_socket(AF_INET, SOCK_DGRAM);
    if (sock == -1) {
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }
    s->type = NABTO_IPV4;
    s->sock = sock;
    return NABTO_EC_OK;
}
