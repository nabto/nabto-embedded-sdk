#include "nm_epoll.h"
#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <platform/np_event_queue.h>
#include <platform/np_communication_buffer.h>

#include <modules/unix/nm_unix_mdns.h>
#include <modules/unix/nm_unix_get_local_ip.h>

#include <modules/posix/nm_posix_udp.h>

#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>

#define LOG NABTO_LOG_MODULE_UDP

struct nm_epoll_udp_send_base {
    struct nm_epoll_udp_send_base* next;
    struct nm_epoll_udp_send_base* prev;
};

struct send_context {
    np_udp_socket* sock;
    np_udp_packet_sent_callback cb;
    void* cbUserData;
    struct np_event ev;
};

struct nm_epoll_created_ctx {
    np_udp_socket_created_callback cb;
    void* data;
    struct np_event event;
};

struct nm_epoll_received_ctx {
    np_udp_packet_received_callback cb;
    void* data;
    struct np_event event;
};

struct np_udp_socket {
    enum nm_epoll_type type;
    struct nm_epoll_base* next;
    struct nm_epoll_base* prev;
    struct np_platform* pl;
    struct nm_posix_udp_socket posixSocket;
    bool aborted;
    struct nm_epoll_created_ctx created;
    struct nm_epoll_received_ctx recv;
    struct np_event abortEv;
};

static np_error_code nm_epoll_create(struct np_platform* pl, np_udp_socket** sock);
static void nm_epoll_destroy(np_udp_socket* sock);
static np_error_code nm_epoll_abort(np_udp_socket* sock);


static np_error_code nm_epoll_async_bind_mdns_ipv4(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);

static np_error_code nm_epoll_async_bind_mdns_ipv6(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);

/**
 * async functions implementing epoll functionallity for the udp
 * interface of <platform/udp.h> used in the np_platform.
 * Defined in .h file for testing purposes
 */
static np_error_code nm_epoll_async_bind_port(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data);
static np_error_code nm_epoll_async_send_to(np_udp_socket* sock, struct np_udp_endpoint ep,
                                            uint8_t* buffer, uint16_t bufferSize,
                                            np_udp_packet_sent_callback cb, void* userData);
static np_error_code nm_epoll_async_recv_from(np_udp_socket* socket,
                                              np_udp_packet_received_callback cb, void* data);
static enum np_ip_address_type nm_epoll_get_protocol(np_udp_socket* socket);
static uint16_t nm_epoll_get_local_port(np_udp_socket* socket);
static void nm_epoll_udp_try_read(void* userData);

void nm_epoll_cancel_all_events(np_udp_socket* sock)
{
    NABTO_LOG_TRACE(LOG, "Cancelling all events");
    np_event_queue_cancel_event(sock->pl, &sock->created.event);
    np_event_queue_cancel_event(sock->pl, &sock->recv.event);
    np_event_queue_cancel_event(sock->pl, &sock->abortEv);
}

void nm_epoll_udp_init(struct nm_epoll_context* epoll, struct np_platform* pl)
{
    pl->udp.create      = &nm_epoll_create;
    pl->udp.destroy     = &nm_epoll_destroy;
    pl->udp.abort       = &nm_epoll_abort;
    pl->udp.async_bind_port   = &nm_epoll_async_bind_port;
    pl->udp.async_bind_mdns_ipv4 = &nm_epoll_async_bind_mdns_ipv4;
    pl->udp.async_bind_mdns_ipv6 = &nm_epoll_async_bind_mdns_ipv6;
    pl->udp.async_send_to     = &nm_epoll_async_send_to;
    pl->udp.async_recv_from   = &nm_epoll_async_recv_from;
    pl->udp.get_protocol      = &nm_epoll_get_protocol;
    pl->udp.get_local_ip      = &nm_unix_get_local_ip;
    pl->udp.get_local_port    = &nm_epoll_get_local_port;
    pl->udpData = epoll;

}

enum np_ip_address_type nm_epoll_get_protocol(np_udp_socket* socket)
{
    return socket->posixSocket.type;
}

uint16_t nm_epoll_get_local_port(np_udp_socket* socket)
{
    if (socket->aborted) {
        NABTO_LOG_ERROR(LOG, "get local port called on aborted socket");
        return 0;
    }
    struct sockaddr_in6 addr;
    addr.sin6_port = 0;
    socklen_t length = sizeof(struct sockaddr_in6);
    getsockname(socket->posixSocket.sock, (struct sockaddr*)(&addr), &length);
    return htons(addr.sin6_port);
}

void nm_epoll_udp_handle_event(np_udp_socket* sock, uint32_t events)
{
    // post event such that the read is executed on the main thread instead of the network thread
    np_event_queue_post_maybe_double(sock->pl, &sock->recv.event, nm_epoll_udp_try_read, sock);
    //nm_epoll_udp_try_read(sock);
}

void nm_epoll_udp_try_read(void* userData)
{
    np_udp_socket* sock = userData;
    if (sock->recv.cb == NULL || sock->aborted) {
        // ignore read on aborted socket, callback is resolved in nm_epoll_udp_event_abort
        return;
    }
    struct np_udp_endpoint ep;
    struct np_platform* pl = sock->pl;
    struct nm_epoll_context* epoll = pl->udpData;
    ssize_t recvLength;
    uint8_t* start;
    start = pl->buf.start(epoll->recvBuffer);
    if (sock->posixSocket.type == NABTO_IPV6) {
        struct sockaddr_in6 sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->posixSocket.sock, start,  pl->buf.size(epoll->recvBuffer), 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.ip.v6, &sa.sin6_addr.s6_addr, sizeof(ep.ip.ip.v6));
        ep.port = ntohs(sa.sin6_port);
        ep.ip.type = NABTO_IPV6;
    } else {
        struct sockaddr_in sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->posixSocket.sock, start, pl->buf.size(epoll->recvBuffer), 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.ip.v4, &sa.sin_addr.s_addr, sizeof(ep.ip.ip.v4));
        ep.port = ntohs(sa.sin_port);
        ep.ip.type = NABTO_IPV4;
    }
    if (recvLength < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK) {
            // expected
            return;
        } else {
            np_udp_packet_received_callback cb;
            NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_epoll_udp_handle_event", strerror(status), (int) status);
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
        cb(NABTO_EC_OK, ep, pl->buf.start(epoll->recvBuffer), recvLength, sock->recv.data);
    }
    np_event_queue_post_maybe_double(pl, &sock->recv.event, nm_epoll_udp_try_read, userData);
}

np_error_code nm_epoll_create(struct np_platform* pl, np_udp_socket** sock)
{
    *sock = calloc(1, sizeof(np_udp_socket));
    if (*sock == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    (*sock)->type = NM_EPOLL_TYPE_UDP;
    (*sock)->pl = pl;
    np_event_queue_init_event(&(*sock)->recv.event);
    nm_epoll_add_udp_socket(pl->udpData);
    return NABTO_EC_OK;
}

void nm_epoll_udp_event_abort(void* userData)
{
    np_udp_socket* sock = (np_udp_socket*)userData;
    if (sock->recv.cb != NULL) {
        struct np_udp_endpoint ep;
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
    np_event_queue_post(sock->pl, &sock->abortEv, &nm_epoll_udp_event_abort, sock);
    return NABTO_EC_OK;
}

void nm_epoll_destroy(np_udp_socket* sock)
{
    if (sock == NULL) {
        NABTO_LOG_ERROR(LOG, "socket destroyed twice");
        return;
    }
    nm_epoll_close_socket(sock->pl->udpData, (struct nm_epoll_base*)sock);
    nm_epoll_break_wait(sock->pl->udpData);
}

void nm_epoll_udp_resolve_close(struct nm_epoll_base* base)
{
    np_udp_socket* sock = (np_udp_socket*)base;
    struct nm_epoll_context* epoll = sock->pl->udpData;
    if (sock->posixSocket.sock != -1) {
        close(sock->posixSocket.sock);
        shutdown(sock->posixSocket.sock, SHUT_RDWR);

        if (epoll_ctl(epoll->fd, EPOLL_CTL_DEL, sock->posixSocket.sock, NULL) == -1) {
            NABTO_LOG_TRACE(LOG,"Cannot remove fd: %d from epoll set, %i: %s", sock->posixSocket.sock, errno, strerror(errno));
        }
    }
    nm_epoll_cancel_all_events(sock);
    nm_epoll_remove_udp_socket(sock->pl->udpData);
    free(sock);
}

void event_bind_callback(void* data)
{
    np_udp_socket* us = (np_udp_socket*)data;
    np_udp_socket_created_callback cb = us->created.cb;
    us->created.cb = NULL;
    cb(NABTO_EC_OK, us->created.data);
    return;
}

np_error_code nm_epoll_async_bind_port(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    struct np_platform* pl = sock->pl;
    struct nm_epoll_context* epoll = pl->udpData;

    np_error_code ec;

    ec = nm_posix_udp_create_socket_any(&sock->posixSocket);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = nm_posix_bind_port(&sock->posixSocket, port);
    if (ec != NABTO_EC_OK) {
        close(sock->posixSocket.sock);
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = sock;
    if (epoll_ctl(epoll->fd, EPOLL_CTL_ADD, sock->posixSocket.sock, &ev) == -1) {
        NABTO_LOG_ERROR(LOG,"could not add file descriptor to epoll set: (%i) '%s'", errno, strerror(errno));
        close(sock->posixSocket.sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, event_bind_callback, sock);
    return NABTO_EC_OK;
}

np_error_code nm_epoll_async_bind_mdns_ipv4(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    struct np_platform* pl = sock->pl;
    struct nm_epoll_context* epoll = pl->udpData;

    np_error_code ec;
    ec = nm_posix_udp_create_socket_ipv4(&sock->posixSocket);

    if (ec != NABTO_EC_OK) {
        return ec;
    }

    if (!nm_unix_init_mdns_ipv4_socket(sock->posixSocket.sock)) {
        close(sock->posixSocket.sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = sock;
    if (epoll_ctl(epoll->fd, EPOLL_CTL_ADD, sock->posixSocket.sock, &ev) == -1) {
        NABTO_LOG_ERROR(LOG,"could not add file descriptor to epoll set: (%i) '%s'", errno, strerror(errno));
        close(sock->posixSocket.sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    nm_unix_mdns_update_ipv4_socket_registration(sock->posixSocket.sock);

    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, event_bind_callback, sock);
    return NABTO_EC_OK;
}


np_error_code nm_epoll_async_bind_mdns_ipv6(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    struct np_platform* pl = sock->pl;
    struct nm_epoll_context* epoll = pl->udpData;

    np_error_code ec = nm_posix_udp_create_socket_ipv6(&sock->posixSocket);
    if (ec) {
        return ec;
    }

    int no = 0;
    int status = setsockopt(sock->posixSocket.sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no));
    if (status < 0)
    {
        NABTO_LOG_ERROR(LOG, "Cannot set IPV6_V6ONLY");
    }

    if (!nm_unix_init_mdns_ipv6_socket(sock->posixSocket.sock)) {
        close(sock->posixSocket.sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = sock;
    if (epoll_ctl(epoll->fd, EPOLL_CTL_ADD, sock->posixSocket.sock, &ev) == -1) {
        NABTO_LOG_ERROR(LOG,"could not add file descriptor to epoll set: (%i) '%s'", errno, strerror(errno));
        close(sock->posixSocket.sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    nm_unix_mdns_update_ipv6_socket_registration(sock->posixSocket.sock);

    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, event_bind_callback, sock);
    return NABTO_EC_OK;
}

void async_send_to_complete(void* data)
{
    struct send_context* sendCtx = data;
    sendCtx->cb(NABTO_EC_OK, sendCtx->cbUserData);
    free(sendCtx);
}

np_error_code nm_epoll_async_send_to(np_udp_socket* sock, struct np_udp_endpoint ep,
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

    np_error_code ec = nm_posix_udp_send_to(&sock->posixSocket, &ep, buffer, bufferSize);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    np_event_queue_post(sock->pl, &sendCtx->ev, async_send_to_complete, sendCtx);
    return NABTO_EC_OK;
}

np_error_code nm_epoll_async_recv_from(np_udp_socket* socket,
                                       np_udp_packet_received_callback cb, void* data)
{
    if (socket->aborted) {
        NABTO_LOG_ERROR(LOG, "recv from called on aborted socket");
        return NABTO_EC_ABORTED;
    }
    if (socket->recv.cb != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    struct np_platform* pl = socket->pl;

    socket->recv.cb = cb;
    socket->recv.data = data;

    // if we received multiple packets in one epoll_wait the event
    // will not be triggered between recv callbacks
    np_event_queue_post_maybe_double(pl, &socket->recv.event, nm_epoll_udp_try_read, socket);
    return NABTO_EC_OK;
}
