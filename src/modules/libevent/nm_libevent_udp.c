#include "nm_libevent.h"
#include "nm_libevent_types.h"
#include "nm_libevent_get_local_ip.h"

#include <platform/np_logging.h>
#include <platform/np_completion_event.h>

#include <event2/util.h>
#include <event2/event.h>
#include <event.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <stdlib.h>
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

#define LOG NABTO_LOG_MODULE_UDP

struct received_ctx {
    struct np_completion_event* completionEvent;
};


struct np_udp_socket {
    struct received_ctx recv;
    enum np_ip_address_type type;
    evutil_socket_t sock;
    struct nm_libevent_context* impl;
    bool aborted;
    struct event* event;
};

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

static void udp_ready_callback(evutil_socket_t s, short events, void* userData);

static uint16_t udp_get_local_port(struct np_udp_socket* socket);

static np_error_code udp_create_socket_any(struct np_udp_socket* s);
static np_error_code udp_bind_port(struct np_udp_socket* s, uint16_t port);
static np_error_code udp_send_to(struct np_udp_socket* s, const struct np_udp_endpoint* ep, const uint8_t* buffer, uint16_t bufferSize);
static void complete_recv_wait(struct np_udp_socket* sock, np_error_code ec);

static struct np_udp_functions mtable = {
    .create               = &udp_create,
    .destroy              = &udp_destroy,
    .abort                = &udp_abort,
    .async_bind_port      = &udp_async_bind_port,
    .async_send_to        = &udp_async_send_to,
    .async_recv_wait      = &udp_async_recv_wait,
    .recv_from            = &udp_recv_from,
    .get_local_port       = &udp_get_local_port
};

struct np_udp nm_libevent_udp_get_impl(struct nm_libevent_context* ctx)
{
    struct np_udp obj;
    obj.mptr = &mtable;
    obj.data = ctx;
    return obj;
}

np_error_code udp_create(struct np_udp* obj, struct np_udp_socket** sock)
{
    struct np_udp_socket* s = calloc(1, sizeof(struct np_udp_socket));
    if (s == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    struct nm_libevent_context* ctx = obj->data;

    s->impl = ctx;

    *sock = s;

    return NABTO_EC_OK;
}

void nm_libevent_udp_add_to_libevent(struct np_udp_socket* sock)
{
    struct nm_libevent_context* context = sock->impl;
    sock->event = event_new(context->eventBase, sock->sock, EV_READ, udp_ready_callback, sock);
}

void udp_abort(struct np_udp_socket* sock)
{
    if (sock->aborted) {
        return;
    }
    sock->aborted = true;
    complete_recv_wait(sock, NABTO_EC_ABORTED);
}

void complete_recv_wait(struct np_udp_socket* sock, np_error_code ec)
{
    if (sock->recv.completionEvent != NULL) {
        struct np_completion_event* ev = sock->recv.completionEvent;
        sock->recv.completionEvent = NULL;
        np_completion_event_resolve(ev, ec);
    }
}

void udp_ready_callback(evutil_socket_t s, short events, void* userData)
{
    struct np_udp_socket* sock = userData;
    if (events & EV_READ) {
        complete_recv_wait(sock, NABTO_EC_OK);
    }
}

void udp_destroy(struct np_udp_socket* sock)
{
    if (sock == NULL) {
        NABTO_LOG_ERROR(LOG, "socket destroyed twice");
        return;
    }

    udp_abort(sock);

    if (sock->event) {
        event_del_block(sock->event);
        event_free(sock->event);
        sock->event = NULL;
    }
    free(sock);
}

np_error_code udp_async_bind_port_ec(struct np_udp_socket* sock, uint16_t port)
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
        evutil_closesocket(sock->sock);
    }
    nm_libevent_udp_add_to_libevent(sock);
    return NABTO_EC_OK;
}

void udp_async_bind_port(struct np_udp_socket* sock, uint16_t port, struct np_completion_event* completionEvent)
{
    np_error_code ec = udp_async_bind_port_ec(sock, port);
    np_completion_event_resolve(completionEvent, ec);
}

np_error_code udp_async_send_to_ec(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
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

    event_add(sock->event, 0);
    return;
}

evutil_socket_t nm_libevent_udp_create_nonblocking_socket(int domain, int type)
{
#if defined(SOCK_NONBLOCK)
    type |= SOCK_NONBLOCK;
#endif

    evutil_socket_t sock = socket(domain, type, 0);

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
        int status = EVUTIL_SOCKET_ERROR();
        NABTO_LOG_TRACE(LOG, "UDP returned error status (%d) %s", status, evutil_socket_error_to_string(status));
        if (ERR_IS_EAGAIN(status)) {
            // expected
            // just drop the packet and the upper layers will take care of retransmissions.
        } else if (ERR_IS_EXPECTED(status)) {
            NABTO_LOG_TRACE(LOG,"ERROR: (%i) '%s' in udp_send_to", (int) status, strerror(status));
        } else {
            NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in udp_send_to", (int) status, strerror(status));
        }
        return NABTO_EC_FAILED_TO_SEND_PACKET;
    }

    return NABTO_EC_OK;
}

np_error_code udp_recv_from(struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength)
{
    ssize_type recvLength;
    if (sock->type == NABTO_IPV6) {
        struct sockaddr_in6 sa;
        socklen_type addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, buffer, bufferSize, 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep->ip.ip.v6, &sa.sin6_addr.s6_addr, sizeof(ep->ip.ip.v6));
        ep->port = ntohs(sa.sin6_port);
        ep->ip.type = NABTO_IPV6;
    } else {
        struct sockaddr_in sa;
        socklen_type addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, buffer, bufferSize, 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep->ip.ip.v4, &sa.sin_addr.s_addr, sizeof(ep->ip.ip.v4));
        ep->port = ntohs(sa.sin_port);
        ep->ip.type = NABTO_IPV4;
    }

    if (recvLength < 0) {
        int status = EVUTIL_SOCKET_ERROR();
        if (ERR_IS_EAGAIN(status) || ERR_IS_EXPECTED(status)) {
            NABTO_LOG_TRACE(LOG,"(%d) '%s' in udp_recv_from %d", status, evutil_socket_error_to_string(status), sock->sock);
            // expected
            // wait for next event to check for data.
            return NABTO_EC_AGAIN;
        } else {
            NABTO_LOG_ERROR(LOG,"ERROR: (%d) '%s' in udp_recv_from", status, evutil_socket_error_to_string(status));
            return NABTO_EC_UDP_SOCKET_ERROR;
        }
    }
    *readLength = recvLength;
    NABTO_LOG_TRACE(LOG, "Received udp packet of size %d", recvLength);
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

np_error_code udp_create_socket_any(struct np_udp_socket* s)
{
    evutil_socket_t sock = nm_libevent_udp_create_nonblocking_socket(AF_INET6, SOCK_DGRAM);
    if (sock == NM_INVALID_SOCKET) {
        sock = nm_libevent_udp_create_nonblocking_socket(AF_INET, SOCK_DGRAM);
        if (s->sock == NM_INVALID_SOCKET) {
            int e = EVUTIL_SOCKET_ERROR();
            NABTO_LOG_ERROR(LOG, "Unable to create socket: (%i) '%s'.", e, evutil_socket_error_to_string(e));
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        } else {
            NABTO_LOG_WARN(LOG, "IPv4 socket opened since IPv6 socket creation failed");
            s->type = NABTO_IPV4;
        }
    } else {
        NABTO_LOG_TRACE(LOG, "Opened socket %d", sock);
        int no = 0;
        s->type = NABTO_IPV6;
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no)))
        {
            int e = EVUTIL_SOCKET_ERROR();
            NABTO_LOG_ERROR(LOG,"Unable to set option: (%i) '%s'.", e, evutil_socket_error_to_string(e));

            evutil_closesocket(s->sock);
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        }
    }
    s->sock = sock;
    return NABTO_EC_OK;
}
