#include "nm_libevent_udp.h"
#include "nm_libevent.h"
#include "nm_libevent_types.h"
#include "nm_libevent_mdns.h"
#include "nm_libevent_get_local_ip.h"

#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <platform/np_event_queue.h>

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

struct send_context {
    np_udp_socket* sock;
    np_udp_packet_sent_callback cb;
    void* cbUserData;
    struct np_event ev;
};

struct created_ctx {
    np_udp_socket_created_callback cb;
    void* data;
    struct np_event event;
};

struct received_ctx {
    np_udp_packet_received_callback cb;
    void* data;
    struct np_event event;
};


struct np_udp_socket {
    struct received_ctx recv;
    enum np_ip_address_type type;
    np_communication_buffer* recvBuffer;
    evutil_socket_t sock;
    struct np_platform* pl;
    bool aborted;
    struct created_ctx created;
    struct np_event abortEv;
    struct event event;
};

static np_error_code udp_create(struct np_platform* pl, np_udp_socket** sock);
static void udp_destroy(np_udp_socket* sock);
static np_error_code udp_abort(np_udp_socket* sock);
static void udp_event_abort(void* userData);
static np_error_code udp_async_bind_port(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data);
static np_error_code udp_async_bind_mdns_ipv4(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);
static np_error_code udp_async_bind_mdns_ipv6(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);
static np_error_code udp_async_send_to(np_udp_socket* sock, struct np_udp_endpoint ep,
                                       uint8_t* buffer, uint16_t bufferSize,
                                       np_udp_packet_sent_callback cb, void* userData);

static np_error_code udp_async_recv_from(np_udp_socket* socket,
                                         np_udp_packet_received_callback cb, void* data);

static void udp_ready_callback(evutil_socket_t s, short events, void* userData);

static enum np_ip_address_type udp_get_protocol(np_udp_socket* socket);
static uint16_t udp_get_local_port(np_udp_socket* socket);


static np_error_code udp_create_socket_ipv4(struct np_udp_socket* s);
static np_error_code udp_create_socket_ipv6(struct np_udp_socket* s);
static np_error_code udp_create_socket_any(struct np_udp_socket* s);
static np_error_code udp_bind_port(struct np_udp_socket* s, uint16_t port);
static void udp_event_try_recv_from(void* userData);
static np_error_code udp_send_to(struct np_udp_socket* s, const struct np_udp_endpoint* ep, const uint8_t* buffer, uint16_t bufferSize);
static evutil_socket_t nonblocking_socket(int domain, int type);


void nm_libevent_udp_init(struct np_platform* pl, struct nm_libevent_context* ctx)
{
    pl->udpData = ctx;

    pl->udp.create               = &udp_create;
    pl->udp.destroy              = &udp_destroy;
    pl->udp.abort                = &udp_abort;
    pl->udp.async_bind_port      = &udp_async_bind_port;
    pl->udp.async_bind_mdns_ipv4 = &udp_async_bind_mdns_ipv4;
    pl->udp.async_bind_mdns_ipv6 = &udp_async_bind_mdns_ipv6;
    pl->udp.async_send_to        = &udp_async_send_to;
    pl->udp.async_recv_from      = &udp_async_recv_from;
    pl->udp.get_protocol         = &udp_get_protocol;
    pl->udp.get_local_ip         = &nm_libevent_get_local_ip;
    pl->udp.get_local_port       = &udp_get_local_port;
}

void nm_libevent_udp_deinit(struct np_platform* pl)
{
    // TODO
}

enum np_ip_address_type udp_get_protocol(np_udp_socket* sock)
{
    return sock->type;
}

np_error_code udp_create(struct np_platform* pl, np_udp_socket** sock)
{
    np_udp_socket* s = calloc(1, sizeof(struct np_udp_socket));
    if (s == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    struct nm_libevent_context* ctx = pl->udpData;

    s->pl = pl;
    s->recvBuffer = ctx->recvBuffer;
    np_event_queue_init_event(&s->recv.event);

    *sock = s;

    return NABTO_EC_OK;
}

void udp_add_to_libevent(np_udp_socket* sock)
{
    struct np_platform* pl = sock->pl;
    struct nm_libevent_context* context = pl->udpData;
    event_assign(&sock->event, context->eventBase, sock->sock, EV_READ, udp_ready_callback, sock);
}

np_error_code udp_abort(np_udp_socket* sock)
{
    if (sock->aborted) {
        return NABTO_EC_OK;
    }
    sock->aborted = true;
    // TODO
    np_event_queue_post(sock->pl, &sock->abortEv, &udp_event_abort, sock);
    return NABTO_EC_OK;
}

void udp_ready_callback(evutil_socket_t s, short events, void* userData)
{
    np_udp_socket* sock = userData;
    if (events & EV_READ) {
        np_event_queue_post_maybe_double(sock->pl, &sock->recv.event, udp_event_try_recv_from, sock);
    }
}


void udp_event_abort(void* userData)
{
    // TODO
    np_udp_socket* sock = (np_udp_socket*)userData;
    if (sock->recv.cb != NULL) {
        struct np_udp_endpoint ep;
        memset(&ep, 0, sizeof(struct np_udp_endpoint));
        np_udp_packet_received_callback cb = sock->recv.cb;
        sock->recv.cb = NULL;
        cb(NABTO_EC_ABORTED, ep, NULL, 0, sock->recv.data);
    }
    if (sock->created.cb) {
        sock->created.cb(NABTO_EC_ABORTED, sock->created.data);
    }
}

np_error_code nm_epoll_abort(np_udp_socket* sock)
{
    if (sock->aborted) {
        return NABTO_EC_OK;
    }

    sock->aborted = true;
    //TODO
    //np_event_queue_post(sock->pl, &sock->abortEv, &nm_epoll_udp_event_abort, sock);
    return NABTO_EC_OK;
}

void udp_destroy(np_udp_socket* sock)
{
    if (sock == NULL) {
        NABTO_LOG_ERROR(LOG, "socket destroyed twice");
        return;
    }

//    struct nm_libevent_context* libeventContext = sock->pl->udpData;

    event_del_block(&sock->event);

    free(sock);
    // TODO
    //nm_epoll_close_socket(sock->pl->udpData, (struct nm_epoll_base*)sock);
    //nm_epoll_break_wait(sock->pl->udpData);
}


static void event_bind_callback(void* data)
{
    np_udp_socket* us = (np_udp_socket*)data;
    udp_add_to_libevent(us);

    np_udp_socket_created_callback cb = us->created.cb;
    us->created.cb = NULL;
    cb(NABTO_EC_OK, us->created.data);
    return;
}

np_error_code udp_async_bind_port(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    struct np_platform* pl = sock->pl;

    np_error_code ec;

    ec = udp_create_socket_any(sock);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = udp_bind_port(sock, port);
    if (ec != NABTO_EC_OK) {
        evutil_closesocket(sock->sock);
    }

    // TODO add to libevent

    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, &event_bind_callback, sock);
    return NABTO_EC_OK;
}

np_error_code udp_async_bind_mdns_ipv4(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    struct np_platform* pl = sock->pl;

    np_error_code ec;
    ec = udp_create_socket_ipv4(sock);

    if (ec != NABTO_EC_OK) {
        return ec;
    }

    if (!nm_libevent_init_mdns_ipv4_socket(sock->sock)) {
        evutil_closesocket(sock->sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    // TODO add to libevent

    nm_libevent_mdns_update_ipv4_socket_registration(sock->sock);

    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, event_bind_callback, sock);
    return NABTO_EC_OK;
}

np_error_code udp_async_bind_mdns_ipv6(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    struct np_platform* pl = sock->pl;

    np_error_code ec = udp_create_socket_ipv6(sock);
    if (ec) {
        return ec;
    }

    if (!nm_libevent_init_mdns_ipv6_socket(sock->sock)) {
        evutil_closesocket(sock->sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    nm_libevent_mdns_update_ipv6_socket_registration(sock->sock);

    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, event_bind_callback, sock);
    return NABTO_EC_OK;
}


static void async_send_to_complete(void* data)
{
    struct send_context* sendCtx = data;
    sendCtx->cb(NABTO_EC_OK, sendCtx->cbUserData);
    free(sendCtx);
}

np_error_code udp_async_send_to(np_udp_socket* sock, struct np_udp_endpoint ep,
                                uint8_t* buffer, uint16_t bufferSize,
                                np_udp_packet_sent_callback cb, void* userData)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "send to called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    struct send_context* sendCtx = calloc(1, sizeof(struct send_context));
    sendCtx->sock = sock;
    sendCtx->cb = cb;
    sendCtx->cbUserData = userData;

    np_error_code ec = udp_send_to(sock, &ep, buffer, bufferSize);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    np_event_queue_post(sock->pl, &sendCtx->ev, async_send_to_complete, sendCtx);
    return NABTO_EC_OK;
}


np_error_code udp_async_recv_from(np_udp_socket* sock,
                                  np_udp_packet_received_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "recv from called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    if (sock->recv.cb != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }

    struct np_platform* pl = sock->pl;

    sock->recv.cb = cb;
    sock->recv.data = data;

    // if we received multiple packets in one epoll_wait the event
    // will not be triggered between recv callbacks
    np_event_queue_post_maybe_double(pl, &sock->recv.event, udp_event_try_recv_from, sock);

    event_add(&sock->event, 0);

    return NABTO_EC_OK;
}

evutil_socket_t nonblocking_socket(int domain, int type)
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
        int status = EVUTIL_SOCKET_ERROR();
        NABTO_LOG_TRACE(LOG, "UDP returned error status (%d) %s", status, evutil_socket_error_to_string(status));
        if (ERR_IS_EAGAIN(status)) {
            // expected
            // just drop the packet and the upper layers will take care of retransmissions.
        } else if (ERR_IS_EXPECTED(status)) {
            NABTO_LOG_TRACE(LOG,"ERROR: (%i) '%s' in nm_epoll_event_send_to", (int) status, strerror(status));
        } else {
            NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_epoll_event_send_to", (int) status, strerror(status));
        }
        return NABTO_EC_FAILED_TO_SEND_PACKET;
    }

    return NABTO_EC_OK;
}

void udp_event_try_recv_from(void* userData)
{
    struct np_udp_socket* sock = userData;
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
        int status = EVUTIL_SOCKET_ERROR();
        if (ERR_IS_EAGAIN(status)) {
            // expected
            // wait for next event to check for data.
            return;
        } else {
            np_udp_packet_received_callback cb;
            NABTO_LOG_ERROR(LOG,"ERROR: (%d) '%s' in udp_event_try_recv_from", status, evutil_socket_error_to_string(status));
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

uint16_t udp_get_local_port(np_udp_socket* s)
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
    evutil_socket_t sock = nonblocking_socket(AF_INET6, SOCK_DGRAM);
    if (sock == NM_INVALID_SOCKET) {
        sock = nonblocking_socket(AF_INET, SOCK_DGRAM);
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

np_error_code udp_create_socket_ipv6(struct np_udp_socket* s)
{
    evutil_socket_t sock = nonblocking_socket(AF_INET6, SOCK_DGRAM);
    if (sock == NM_INVALID_SOCKET) {
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

np_error_code udp_create_socket_ipv4(struct np_udp_socket* s)
{
    evutil_socket_t sock = nonblocking_socket(AF_INET, SOCK_DGRAM);
    if (sock == NM_INVALID_SOCKET) {
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }
    s->type = NABTO_IPV4;
    s->sock = sock;
    return NABTO_EC_OK;
}
