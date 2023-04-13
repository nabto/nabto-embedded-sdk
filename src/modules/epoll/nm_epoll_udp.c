#include "nm_epoll.h"

#include <platform/np_logging.h>
#include <platform/np_completion_event.h>
#include <platform/np_allocator.h>
#include <platform/interfaces/np_udp.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif


#include <errno.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <sys/epoll.h>

#define LOG NABTO_LOG_MODULE_UDP

static np_error_code udp_create(struct np_udp* obj, struct np_udp_socket** sock);
static void udp_destroy(struct np_udp_socket* sock);
static void udp_abort(struct np_udp_socket* sock);
static void udp_async_bind_port(struct np_udp_socket* sock, uint16_t port, struct np_completion_event* completionEvent);

static void udp_async_send_to(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                              uint8_t* buffer, uint16_t bufferSize,
                              struct np_completion_event* completionEvent);

static void udp_async_recv_wait(struct np_udp_socket* socket,
                                struct np_completion_event* completionEvent);
static np_error_code udp_recv_from(struct np_udp_socket* socket, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength);

static uint16_t udp_get_local_port(struct np_udp_socket* socket);

static np_error_code udp_create_socket_any(struct np_udp_socket* s);
static np_error_code udp_bind_port(struct np_udp_socket* s, uint16_t port);
static np_error_code udp_send_to(struct np_udp_socket* s, const struct np_udp_endpoint* ep, const uint8_t* buffer, uint16_t bufferSize);
static void complete_recv_wait(struct np_udp_socket* sock, np_error_code ec);

static struct np_udp_functions module = {
    .create               = &udp_create,
    .destroy              = &udp_destroy,
    .abort                = &udp_abort,
    .async_bind_port      = &udp_async_bind_port,
    .async_send_to        = &udp_async_send_to,
    .async_recv_wait      = &udp_async_recv_wait,
    .recv_from            = &udp_recv_from,
    .get_local_port       = &udp_get_local_port
};

struct np_udp nm_epoll_udp_get_impl(struct nm_epoll* ctx)
{
    struct np_udp obj;
    obj.mptr = &module;
    obj.data = ctx;
    return obj;
}

np_error_code udp_create(struct np_udp* obj, struct np_udp_socket** sock)
{
    struct np_udp_socket* s = np_calloc(1, sizeof(struct np_udp_socket));
    if (s == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    struct nm_epoll* ctx = obj->data;

    s->impl = ctx;
    s->sock = -1;
    s->epollEvent.data.ptr = s;

    *sock = s;

    return NABTO_EC_OK;
}

void udp_abort(struct np_udp_socket* sock)
{
    if (sock->aborted) {
        return;
    }
    sock->aborted = true;
    complete_recv_wait(sock, NABTO_EC_ABORTED);
}

void update_epoll(struct np_udp_socket* sock) {
    int status = epoll_ctl(sock->impl->epollFd, EPOLL_CTL_MOD, sock->sock, &sock->epollEvent);
    if (status == -1) {
        NABTO_LOG_ERROR(LOG, "epoll_ctl error %s",strerror(errno));
    }
}

void complete_recv_wait(struct np_udp_socket* sock, np_error_code ec)
{
    if (sock->recv.completionEvent != NULL) {
        struct np_completion_event* ev = sock->recv.completionEvent;
        sock->recv.completionEvent = NULL;
        sock->epollEvent.events = 0;
        update_epoll(sock);
        np_completion_event_resolve(ev, ec);
    }
}

void nm_epoll_udp_handle_event(struct np_udp_socket* sock, uint32_t events)
{
    if (events & EPOLLIN) {
        complete_recv_wait(sock, NABTO_EC_OK);
    }
}

void udp_destroy(struct np_udp_socket* sock)
{
    if (sock == NULL) {
        NABTO_LOG_ERROR(LOG, "socket destroyed twice");
        return;
    }

    if (sock->sock != -1) {
        udp_abort(sock);
    }
    // TODO handle ec

    if (sock->sock != -1) {
        int status = epoll_ctl(sock->impl->epollFd, EPOLL_CTL_DEL, sock->sock, NULL);
        if (status == -1) {
           NABTO_LOG_ERROR(LOG, "epoll_ctl error %s",strerror(errno));
        }
        close(sock->sock);
        sock->sock = -1;
    }
    np_free(sock);
}

static np_error_code udp_async_bind_port_ec(struct np_udp_socket* sock, uint16_t port)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec;

    ec = udp_create_socket_any(sock);

    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = udp_bind_port(sock, port);

    if (ec != NABTO_EC_OK) {
        close(sock->sock);
        sock->sock = -1;
        return ec;
    }

    int status = epoll_ctl(sock->impl->epollFd, EPOLL_CTL_ADD, sock->sock, &sock->epollEvent);
    if (status == -1) {
        NABTO_LOG_ERROR(LOG, "epoll_ctl error %s",strerror(errno));
    }

    return NABTO_EC_OK;
}

void udp_async_bind_port(struct np_udp_socket* sock, uint16_t port, struct np_completion_event* completionEvent)
{
    np_error_code ec = udp_async_bind_port_ec(sock, port);
    np_completion_event_resolve(completionEvent, ec);
}

static np_error_code udp_async_send_to_ec(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                   uint8_t* buffer, uint16_t bufferSize)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "send to called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    return udp_send_to(sock, ep, buffer, bufferSize);
}

void udp_async_send_to(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                       uint8_t* buffer, uint16_t bufferSize,
                       struct np_completion_event* completionEvent)
{
    np_error_code ec = udp_async_send_to_ec(sock, ep, buffer, bufferSize);
    np_completion_event_resolve(completionEvent, ec);
}


void udp_async_recv_wait(struct np_udp_socket* sock,
                         struct np_completion_event* completionEvent)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "recv from called on aborted socket");
        np_completion_event_resolve(completionEvent, NABTO_EC_ABORTED);
        return;
    }

    if (sock->recv.completionEvent != NULL) {
        NABTO_LOG_TRACE(LOG, "operation in progress");
        np_completion_event_resolve(completionEvent, NABTO_EC_OPERATION_IN_PROGRESS);
        return;
    }

    sock->recv.completionEvent = completionEvent;

    struct epoll_event event;
    memset(&event, 0, sizeof(struct epoll_event));
    event.events = EPOLLIN;
    event.data.ptr = sock;

    int status = epoll_ctl(sock->impl->epollFd, EPOLL_CTL_MOD, sock->sock, &event);
    if (status == -1) {
        NABTO_LOG_ERROR(LOG, "epoll_ctl error %s",strerror(errno));
    }

    return;
}

int nm_epoll_udp_create_nonblocking_socket(int domain, int type)
{
#if defined(SOCK_NONBLOCK)
    type |= SOCK_NONBLOCK;
#endif

    int sock = socket(domain, type, 0);

#ifndef SOCK_NONBLOCK
#if defined(F_GETFL)
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        NABTO_LOG_ERROR(LOG, "cannot set nonblocking mode, fcntl F_GETFL failed");
        return NM_INVALID_SOCKET;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        NABTO_LOG_ERROR(LOG, "cannot set nonblocking mode, fcntl F_SETFL failed");
        return NM_INVALID_SOCKET;
    }
#elif defined(FIONBIO)
    u_long nonblocking = 1;
    ioctlsocket(sock, FIONBIO, &nonblocking);
#else
    #error cannot make socket nonblocking
#endif
#endif
    return sock;
}

np_error_code udp_send_to(struct np_udp_socket* s, const struct np_udp_endpoint* ep, const uint8_t* buffer, uint16_t bufferSize)
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

    NABTO_LOG_TRACE(LOG, "Sending packet of size %d, to %s, port %d", bufferSize, np_ip_address_to_string(&sendIp), ep->port);
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
        if (ERR_IS_EAGAIN(status)) {
            // expected
            // just drop the packet and the upper layers will take care of retransmissions.
            NABTO_LOG_TRACE(LOG, "Dropping udp packet, the packet will be retransmitted later (%d) %s", status, strerror(status));
            return NABTO_EC_OK;
        } else if (ERR_IS_EXPECTED(status)) {
            NABTO_LOG_TRACE(LOG,"expected sendto status: (%i) '%s'", (int) status, ERR_TO_STRING(status));
        } else {
            NABTO_LOG_ERROR(LOG,"unexpected sendto status (%i) '%s'", (int) status, ERR_TO_STRING(status));
        }
        return NABTO_EC_FAILED_TO_SEND_PACKET;
    }

    return NABTO_EC_OK;
}

np_error_code udp_recv_from(struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength)
{
    ssize_t recvLength;
    if (sock->type == NABTO_IPV6) {
        struct sockaddr_in6 sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, buffer, bufferSize, 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep->ip.ip.v6, &sa.sin6_addr.s6_addr, sizeof(ep->ip.ip.v6));
        ep->port = ntohs(sa.sin6_port);
        ep->ip.type = NABTO_IPV6;
    } else {
        struct sockaddr_in sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, buffer, bufferSize, 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep->ip.ip.v4, &sa.sin_addr.s_addr, sizeof(ep->ip.ip.v4));
        ep->port = ntohs(sa.sin_port);
        ep->ip.type = NABTO_IPV4;
    }

    if (recvLength < 0) {
        int status = errno;
        if (ERR_IS_EAGAIN(status) || ERR_IS_EXPECTED(status)) {
            NABTO_LOG_TRACE(LOG,"(%d) '%s' in udp_recv_from %d", status, strerror(status), sock->sock);
            // expected
            // wait for next event to check for data.
            return NABTO_EC_AGAIN;
        } else {
            NABTO_LOG_ERROR(LOG,"ERROR: (%d) '%s' in udp_recv_from", status, strerror(status));
            return NABTO_EC_UDP_SOCKET_ERROR;
        }
    }
    *readLength = recvLength;
    NABTO_LOG_TRACE(LOG, "Received udp packet of size %d, from %s, port %d ", recvLength, np_ip_address_to_string(&ep->ip), ep->port);
    return NABTO_EC_OK;
}

np_error_code udp_bind_port(struct np_udp_socket* s, uint16_t port)
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
        if (errno == EADDRINUSE) {
            return NABTO_EC_ADDRESS_IN_USE;
        }
        NABTO_LOG_TRACE(LOG, "Could not create UDP socket, errno is %d", errno);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }
}

uint16_t udp_get_local_port(struct np_udp_socket* s)
{
    if (s->aborted) {
        NABTO_LOG_ERROR(LOG, "get local port called on aborted socket");
        return 0;
    }
    if (s->type == NABTO_IPV6) {
        struct sockaddr_in6 addr;
        addr.sin6_port = 0;
        socklen_t length = sizeof(struct sockaddr_in6);
        getsockname(s->sock, (struct sockaddr*)(&addr), &length);
        return htons(addr.sin6_port);
    } else {
        struct sockaddr_in addr;
        addr.sin_port = 0;
        socklen_t length = sizeof(struct sockaddr_in);
        getsockname(s->sock, (struct sockaddr*)(&addr), &length);
        return htons(addr.sin_port);
    }
}

np_error_code udp_create_socket_any(struct np_udp_socket* s)
{
    int sock = nm_epoll_udp_create_nonblocking_socket(AF_INET6, SOCK_DGRAM);
    enum np_ip_address_type type = NABTO_IPV6;
    if (sock == -1) {
        sock = nm_epoll_udp_create_nonblocking_socket(AF_INET, SOCK_DGRAM);
        type = NABTO_IPV4;
        if (sock == -1) {
            int e = errno;
            NABTO_LOG_ERROR(LOG, "Unable to create socket: (%i) '%s'.", e, strerror(e));
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        } else {
            NABTO_LOG_WARN(LOG, "IPv4 socket opened since IPv6 socket creation failed");
        }
    } else {
        NABTO_LOG_TRACE(LOG, "Opened socket %d", sock);
        int no = 0;
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no)))
        {
            int e = errno;
            NABTO_LOG_ERROR(LOG,"Unable to set option: (%i) '%s'.", e, strerror(e));

            close(sock);
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        }
    }
    s->sock = sock;
    s->type = type;
    return NABTO_EC_OK;
}
