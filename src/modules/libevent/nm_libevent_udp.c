#include "nm_libevent_udp.h"
#include "nm_libevent.h"

#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <platform/np_event_queue.h>

#include <modules/posix/nm_posix_udp.h>
#include <modules/unix/nm_unix_mdns.h>

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

struct np_udp_socket {
    struct nm_posix_udp_socket posixSocket;
    struct np_platform* pl;
    bool aborted;
    struct created_ctx created;
    struct np_event abortEv;
    struct event event;
};

static np_error_code udp_create(struct np_platform* pl, np_udp_socket** sock);
static void udp_destroy(np_udp_socket* sock);
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

void nm_libevent_udp_init(struct np_platform* pl, struct nm_libevent_context* ctx)
{
    pl->udpData = ctx;

    pl->udp.create               = &udp_create;
    pl->udp.destroy              = &udp_destroy;
    pl->udp.async_bind_port      = &udp_async_bind_port;
    pl->udp.async_bind_mdns_ipv4 = &udp_async_bind_mdns_ipv4;
    pl->udp.async_bind_mdns_ipv6 = &udp_async_bind_mdns_ipv6;
    pl->udp.async_send_to        = &udp_async_send_to;
    pl->udp.async_recv_from      = &udp_async_recv_from;
    pl->udp.get_protocol         = &udp_get_protocol;
//    pl->udp.get_local_ip         = &udp_get_local_ip;
    pl->udp.get_local_port       = &udp_get_local_port;
}

void nm_libevent_udp_deinit(struct np_platform* pl)
{
    // TODO
}

enum np_ip_address_type udp_get_protocol(np_udp_socket* socket)
{
    return socket->posixSocket.type;
}

uint16_t udp_get_local_port(np_udp_socket* socket)
{
    if (socket->aborted) {
        NABTO_LOG_ERROR(LOG, "get local port called on aborted socket");
        return 0;
    }
    return nm_posix_udp_get_local_port(&socket->posixSocket);
}

np_error_code udp_create(struct np_platform* pl, np_udp_socket** sock)
{
    np_udp_socket* s = calloc(1, sizeof(struct np_udp_socket));
    if (s == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    struct nm_libevent_context* ctx = pl->udpData;

    s->pl = pl;
    s->posixSocket.pl = pl;
    s->posixSocket.recvBuffer = ctx->recvBuffer;
    np_event_queue_init_event(&s->posixSocket.recv.event);

    *sock = s;

    return NABTO_EC_OK;
}

void udp_add_to_libevent(np_udp_socket* sock)
{
    struct np_platform* pl = sock->pl;
    struct nm_libevent_context* context = pl->udpData;
    event_assign(&sock->event, context->eventBase, sock->posixSocket.sock, EV_READ, udp_ready_callback, sock);
}

np_error_code udp_abort(np_udp_socket* sock)
{
    if (sock->aborted) {
        return NABTO_EC_OK;
    }
    sock->aborted = true;
    // TODO
//    np_event_queue_post(sock->pl, &sock->abortEv, &nm_epoll_udp_event_abort, sock);
    return NABTO_EC_OK;
}

void udp_ready_callback(evutil_socket_t s, short events, void* userData)
{
    np_udp_socket* sock = userData;
    if (events & EV_READ) {
        np_event_queue_post_maybe_double(sock->pl, &sock->posixSocket.recv.event, nm_posix_udp_event_try_recv_from, &sock->posixSocket);
    }
}


void udp_event_abort(void* userData)
{
    // TODO
    /* np_udp_socket* sock = (np_udp_socket*)userData; */
    /* if (sock->posixSocket.recv.cb != NULL) { */
    /*     struct np_udp_endpoint ep; */
    /*     np_udp_packet_received_callback cb = sock->posixSocket.recv.cb; */
    /*     sock->posixSocket.recv.cb = NULL; */
    /*     cb(NABTO_EC_ABORTED, ep, NULL, 0, sock->posixSocket.recv.data); */
    /* } */
    /* if (sock->created.cb) { */
    /*     sock->created.cb(NABTO_EC_ABORTED, sock->created.data); */
    /* } */
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

    ec = nm_posix_udp_create_socket_any(&sock->posixSocket);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = nm_posix_bind_port(&sock->posixSocket, port);
    if (ec != NABTO_EC_OK) {
        close(sock->posixSocket.sock);
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
    ec = nm_posix_udp_create_socket_ipv4(&sock->posixSocket);

    if (ec != NABTO_EC_OK) {
        return ec;
    }

    if (!nm_unix_init_mdns_ipv4_socket(sock->posixSocket.sock)) {
        close(sock->posixSocket.sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    // TODO add to libevent

    nm_unix_mdns_update_ipv4_socket_registration(sock->posixSocket.sock);

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

    np_error_code ec = nm_posix_udp_create_socket_ipv6(&sock->posixSocket);
    if (ec) {
        return ec;
    }

    if (!nm_unix_init_mdns_ipv6_socket(sock->posixSocket.sock)) {
        close(sock->posixSocket.sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    // TODO add to libevent


    nm_unix_mdns_update_ipv6_socket_registration(sock->posixSocket.sock);

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

    np_error_code ec = nm_posix_udp_send_to(&sock->posixSocket, &ep, buffer, bufferSize);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    np_event_queue_post(sock->pl, &sendCtx->ev, async_send_to_complete, sendCtx);
    return NABTO_EC_OK;
}


np_error_code udp_async_recv_from(np_udp_socket* socket,
                                  np_udp_packet_received_callback cb, void* data)
{
    if (socket->aborted) {
        NABTO_LOG_ERROR(LOG, "recv from called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    if (socket->posixSocket.recv.cb != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }

    struct np_platform* pl = socket->pl;

    socket->posixSocket.recv.cb = cb;
    socket->posixSocket.recv.data = data;

    // if we received multiple packets in one epoll_wait the event
    // will not be triggered between recv callbacks
    np_event_queue_post_maybe_double(pl, &socket->posixSocket.recv.event, nm_posix_udp_event_try_recv_from, &socket->posixSocket);

    event_add(&socket->event, 0);

    return NABTO_EC_OK;
}
