#include "nm_select_unix_udp.h"

#include <platform/np_logging.h>
#include <platform/np_util.h>

#include <modules/unix/nm_unix_mdns.h>
#include <modules/unix/nm_unix_get_local_ip.h>
#include <modules/posix/nm_posix_udp.h>

#include <stdlib.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#define LOG NABTO_LOG_MODULE_UDP

static const struct np_udp_endpoint emptyEp;

struct send_context {
    np_udp_socket* sock;
    np_udp_packet_sent_callback cb;
    void* cbUserData;
    struct np_event ev;
};

/**
 * Helper function declarations
 */
static void nm_select_unix_udp_cancel_all_events(np_udp_socket* sock);
static void nm_select_unix_udp_handle_event(np_udp_socket* sock);
static void nm_select_unix_udp_free_socket(np_udp_socket* sock);

/**
 * Api function declarations
 */
static np_error_code nm_select_unix_udp_create(struct np_platform* pl, np_udp_socket** sock);
static void nm_select_unix_udp_destroy(np_udp_socket* sock);
static np_error_code nm_select_unix_udp_abort(np_udp_socket* sock);
static np_error_code nm_select_unix_udp_async_bind_port(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data);
static np_error_code nm_select_unix_async_bind_mdns_ipv4(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);
static np_error_code nm_select_unix_async_bind_mdns_ipv6(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);
static np_error_code nm_select_unix_udp_async_send_to(np_udp_socket* sock, struct np_udp_endpoint ep,
                                                      uint8_t* buffer, uint16_t bufferSize,
                                                      np_udp_packet_sent_callback cb, void* userData);
static np_error_code nm_select_unix_udp_async_recv_from(np_udp_socket* socket,
                                                        np_udp_packet_received_callback cb, void* data);
static enum np_ip_address_type nm_select_unix_udp_get_protocol(np_udp_socket* socket);
static uint16_t nm_select_unix_udp_get_local_port(np_udp_socket* socket);

np_error_code nm_select_unix_udp_init(struct nm_select_unix* ctx, struct np_platform *pl)
{
    struct nm_select_unix_udp_sockets* sockets = &ctx->udpSockets;
    pl->udp.create           = &nm_select_unix_udp_create;
    pl->udp.destroy          = &nm_select_unix_udp_destroy;
    pl->udp.abort            = &nm_select_unix_udp_abort;
    pl->udp.async_bind_port  = &nm_select_unix_udp_async_bind_port;
    pl->udp.async_bind_mdns_ipv4 = &nm_select_unix_async_bind_mdns_ipv4;
    pl->udp.async_bind_mdns_ipv6 = &nm_select_unix_async_bind_mdns_ipv6;
    pl->udp.async_send_to    = &nm_select_unix_udp_async_send_to;
    pl->udp.async_recv_from  = &nm_select_unix_udp_async_recv_from;
    pl->udp.get_protocol     = &nm_select_unix_udp_get_protocol;
    pl->udp.get_local_ip     = &nm_unix_get_local_ip;
    pl->udp.get_local_port   = &nm_select_unix_udp_get_local_port;
    pl->udpData = ctx;

    sockets->recvBuf = pl->buf.allocate();
    if (!sockets->recvBuf) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    sockets->socketsSentinel.next = &sockets->socketsSentinel;
    sockets->socketsSentinel.prev = &sockets->socketsSentinel;
    return NABTO_EC_OK;
}

void nm_select_unix_udp_deinit(struct nm_select_unix* ctx)
{
    ctx->pl->buf.free(ctx->udpSockets.recvBuf);
}

bool nm_select_unix_udp_has_sockets(struct nm_select_unix* ctx)
{
    return ctx->udpSockets.socketsSentinel.next == &ctx->udpSockets.socketsSentinel;
}


np_error_code nm_select_unix_udp_create(struct np_platform* pl, np_udp_socket** sock)
{
    np_udp_socket* s = calloc(1, sizeof(np_udp_socket));
    if (!s) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    *sock = s;
    s->posixSocket.sock = -1;

    struct nm_select_unix* selectCtx = pl->udpData;
    struct nm_select_unix_udp_sockets* sockets = &selectCtx->udpSockets;

    s->pl = selectCtx->pl;
    s->selectCtx = pl->udpData;
    s->destroyed = false;
    s->aborted = false;

    np_udp_socket* before = sockets->socketsSentinel.prev;
    np_udp_socket* after = &sockets->socketsSentinel;
    before->next = s;
    s->next = after;
    after->prev = s;
    s->prev = before;

    s->posixSocket.pl = pl;
    s->posixSocket.recvBuffer = selectCtx->udpSockets.recvBuf;
    np_event_queue_init_event(&s->posixSocket.recv.event);

    // add fd to select fd set.
    nm_select_unix_notify(selectCtx);

    return NABTO_EC_OK;
}

static void event_bind_callback(void* data)
{
    np_udp_socket* us = (np_udp_socket*)data;
    np_udp_socket_created_callback cb = us->created.cb;
    us->created.cb = NULL;
    cb(NABTO_EC_OK, us->created.data);
    return;
}

np_error_code nm_select_unix_udp_async_bind_port(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }
    struct np_platform* pl = sock->pl;

    np_error_code ec;

    ec = nm_posix_udp_create_socket_any(&sock->posixSocket);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = nm_posix_bind_port(&sock->posixSocket, port);
    if (ec != NABTO_EC_OK) {
        close(sock->posixSocket.sock);
    }

    sock->created.cb = cb;
    sock->created.data = data;
    sock->created.port = port;
    np_event_queue_post(pl, &sock->created.event, &event_bind_callback, sock);
    return NABTO_EC_OK;
}

np_error_code nm_select_unix_async_bind_mdns_ipv4(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }
    struct np_platform* pl = sock->pl;

    np_error_code ec;
    ec = nm_posix_udp_create_socket_ipv4(&sock->posixSocket);

    if (ec != NABTO_EC_OK) {
        return ec;
    }

    if (!nm_unix_init_mdns_ipv4_socket(sock->posixSocket.sock)) {
        close(sock->posixSocket.sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    nm_unix_mdns_update_ipv4_socket_registration(sock->posixSocket.sock);

    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, &event_bind_callback, sock);
    return NABTO_EC_OK;
}

np_error_code nm_select_unix_async_bind_mdns_ipv6(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }
    struct np_platform* pl = sock->pl;

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

    nm_unix_mdns_update_ipv6_socket_registration(sock->posixSocket.sock);

    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, &event_bind_callback, sock);
    return NABTO_EC_OK;
}

static void async_send_to_complete(void* data)
{
    struct send_context* sendCtx = data;
    sendCtx->cb(NABTO_EC_OK, sendCtx->cbUserData);
    free(sendCtx);
}

np_error_code nm_select_unix_udp_async_send_to(np_udp_socket* sock, struct np_udp_endpoint ep,
                                               uint8_t* buffer, uint16_t bufferSize,
                                               np_udp_packet_sent_callback cb, void* userData)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "send to called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    struct send_context* sendCtx = calloc(1, sizeof(struct send_context));
    if (sendCtx == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    sendCtx->sock = sock;
    sendCtx->cb = cb;
    sendCtx->cbUserData = userData;

    np_error_code ec = nm_posix_udp_send_to(&sock->posixSocket, &ep, buffer, bufferSize);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    np_event_queue_post(sock->pl, &sendCtx->ev, &async_send_to_complete, sendCtx);
    return NABTO_EC_OK;
}


np_error_code nm_select_unix_udp_async_recv_from(np_udp_socket* socket,
                                                 np_udp_packet_received_callback cb, void* data)
{
    if (socket->aborted) {
        NABTO_LOG_ERROR(LOG, "recv from called on aborted socket");
        return NABTO_EC_ABORTED;
    }
    socket->posixSocket.recv.cb = cb;
    socket->posixSocket.recv.data = data;
    nm_select_unix_notify(socket->selectCtx);
    return NABTO_EC_OK;
}

enum np_ip_address_type nm_select_unix_udp_get_protocol(np_udp_socket* socket)
{
    return socket->posixSocket.type;
}

uint16_t nm_select_unix_udp_get_local_port(np_udp_socket* socket)
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

void nm_select_unix_udp_event_abort(void* userData)
{
    np_udp_socket* sock = (np_udp_socket*)userData;
    if (sock->posixSocket.recv.cb != NULL) {
        struct np_udp_endpoint ep = emptyEp;
        np_udp_packet_received_callback cb = sock->posixSocket.recv.cb;
        sock->posixSocket.recv.cb = NULL;
        cb(NABTO_EC_ABORTED, ep, NULL, 0, sock->posixSocket.recv.data);
    }
    if (sock->created.cb) {
        np_udp_socket_created_callback cb = sock->created.cb;
        sock->created.cb = NULL;
        cb(NABTO_EC_ABORTED, sock->created.data);
    }
}

np_error_code nm_select_unix_udp_abort(np_udp_socket* sock)
{
    if (!sock->aborted) {
        sock->aborted = true;
        np_event_queue_post(sock->pl, &sock->abortEv, &nm_select_unix_udp_event_abort, sock);
    }
    return NABTO_EC_OK;
}

void nm_select_unix_udp_destroy(np_udp_socket* sock)
{
    if (sock == NULL) {
        return;
    }
    sock->destroyed = true;
    nm_select_unix_notify(sock->selectCtx);
    return;
}

void nm_select_unix_udp_handle_event(np_udp_socket* sock)
{
    np_event_queue_post_maybe_double(sock->pl, &sock->posixSocket.recv.event, nm_posix_udp_event_try_recv_from, &sock->posixSocket);
}

void nm_select_unix_udp_free_socket(np_udp_socket* sock)
{
    np_udp_socket* before = sock->prev;
    np_udp_socket* after = sock->next;
    before->next = after;
    after->prev = before;

    shutdown(sock->posixSocket.sock, SHUT_RDWR);
    close(sock->posixSocket.sock);
    nm_select_unix_udp_cancel_all_events(sock);
    free(sock);
}

void nm_select_unix_udp_cancel_all_events(np_udp_socket* sock)
{
    struct np_platform* pl = sock->pl;
    NABTO_LOG_TRACE(LOG, "Cancelling all events");
    np_event_queue_cancel_event(pl, &sock->created.event);
    np_event_queue_cancel_event(pl, &sock->posixSocket.recv.event);
    np_event_queue_cancel_event(pl, &sock->abortEv);
}

void nm_select_unix_udp_build_fd_sets(struct nm_select_unix* ctx, struct nm_select_unix_udp_sockets* sockets)
{
    np_udp_socket* iterator = sockets->socketsSentinel.next;

    while(iterator != &sockets->socketsSentinel)
    {
        if (iterator->posixSocket.recv.cb && iterator->posixSocket.sock != -1) {
            FD_SET(iterator->posixSocket.sock, &ctx->readFds);
            ctx->maxReadFd = NP_MAX(ctx->maxReadFd, iterator->posixSocket.sock);
        }
        iterator = iterator->next;
    }
}

void nm_select_unix_udp_handle_select(struct nm_select_unix* ctx, int nfds)
{
    struct nm_select_unix_udp_sockets* sockets = &ctx->udpSockets;
    np_udp_socket* iterator = sockets->socketsSentinel.next;
    while(iterator != &sockets->socketsSentinel)
    {
        if (iterator->destroyed) {
            np_udp_socket* current = iterator;
            iterator = iterator->next;
            nm_select_unix_udp_free_socket(current);
            continue;
        }
        if (iterator->posixSocket.sock != -1 && FD_ISSET(iterator->posixSocket.sock, &ctx->readFds)) {
            nm_select_unix_udp_handle_event(iterator);
        }
        iterator = iterator->next;
    }
}
