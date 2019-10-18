#include "nm_select_unix_tcp.h"

#include <platform/np_util.h>
#include <platform/np_logging.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define LOG NABTO_LOG_MODULE_TCP

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static np_error_code create(struct np_platform* pl, np_tcp_socket** sock);
static void destroy(np_tcp_socket* sock);
static np_error_code async_connect(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, np_tcp_connect_callback cb, void* userData);
static np_error_code async_write(np_tcp_socket* sock, const void* data, size_t dataLength, np_tcp_write_callback cb, void* userData);
static np_error_code async_read(np_tcp_socket* sock, void* buffer, size_t bufferLength, np_tcp_read_callback cb, void* userData);
static np_error_code tcp_shutdown(np_tcp_socket* sock);
static np_error_code tcp_close(np_tcp_socket* sock);

static void is_connected(void* userData);
static void tcp_do_write(np_tcp_socket* sock);
static void tcp_do_read(np_tcp_socket* sock);

void nm_select_unix_tcp_init(struct nm_select_unix* ctx)
{
    struct nm_select_unix_tcp_sockets* sockets = &ctx->tcpSockets;
    sockets->socketsSentinel.next = &sockets->socketsSentinel;
    sockets->socketsSentinel.prev = &sockets->socketsSentinel;

    struct np_platform* pl = ctx->pl;
    pl->tcpData = ctx;
    pl->tcp.create = &create;
    pl->tcp.destroy = &destroy;
    pl->tcp.async_connect = &async_connect;
    pl->tcp.async_write = &async_write;
    pl->tcp.async_read = &async_read;
    pl->tcp.shutdown = &tcp_shutdown;
    pl->tcp.abort = &tcp_close;
}

void nm_select_unix_tcp_deinit(struct nm_select_unix* ctx)
{
    // nothing was allocated in init
}

bool nm_select_unix_tcp_has_sockets(struct nm_select_unix* ctx)
{
    return ctx->tcpSockets.socketsSentinel.next == &ctx->tcpSockets.socketsSentinel;
}

void nm_select_unix_tcp_build_fd_sets(struct nm_select_unix* ctx)
{
    struct nm_select_unix_tcp_sockets* sockets = &ctx->tcpSockets;
    struct np_tcp_socket* iterator = sockets->socketsSentinel.next;
    while (iterator != &sockets->socketsSentinel)
    {
        if (iterator->read.callback != NULL) {
            FD_SET(iterator->fd, &ctx->readFds);
            ctx->maxReadFd = NP_MAX(ctx->maxReadFd, iterator->fd);
        }
        if (iterator->write.callback != NULL || iterator->connectCb != NULL) {
            FD_SET(iterator->fd, &ctx->writeFds);
            ctx->maxWriteFd = NP_MAX(ctx->maxWriteFd, iterator->fd);
        }
        iterator = iterator->next;
    }
}

void nm_select_unix_tcp_cancel_all_events(np_tcp_socket* sock)
{
    struct np_platform* pl = sock->pl;
    NABTO_LOG_TRACE(LOG, "Cancelling all events");
    np_event_queue_cancel_event(pl, &sock->connectEvent);
    np_event_queue_cancel_event(pl, &sock->abortEv);
}

void nm_select_unix_tcp_free_socket(struct np_tcp_socket* sock)
{
    np_tcp_socket* before = sock->prev;
    np_tcp_socket* after = sock->next;
    before->next = after;
    after->prev = before;

    shutdown(sock->fd, SHUT_RDWR);
    close(sock->fd);
    nm_select_unix_tcp_cancel_all_events(sock);
    free(sock);

}

void nm_select_unix_tcp_handle_select(struct nm_select_unix* ctx, int nfds)
{
    struct nm_select_unix_tcp_sockets* sockets = &ctx->tcpSockets;
    struct np_tcp_socket* iterator = sockets->socketsSentinel.next;
    while (iterator != &sockets->socketsSentinel)
    {
        if (iterator->destroyed) {
            np_tcp_socket* current = iterator;
            iterator = iterator->next;
            nm_select_unix_tcp_free_socket(current);
            continue;
        }
        if (FD_ISSET(iterator->fd, &ctx->readFds)) {
            tcp_do_read(iterator);
        }
        if (FD_ISSET(iterator->fd, &ctx->writeFds)) {
            if (iterator->connectCb) {
                is_connected(iterator);
            }
            if (iterator->write.callback) {
                tcp_do_write(iterator);
            }
        }
        iterator = iterator->next;
    }
}


np_error_code create(struct np_platform* pl, np_tcp_socket** sock)
{
    struct nm_select_unix* selectCtx = pl->tcpData;
    struct nm_select_unix_tcp_sockets* sockets = &selectCtx->tcpSockets;
    np_tcp_socket* s = calloc(1,sizeof(struct np_tcp_socket));
    s->pl = pl;
    s->fd = -1;
    *sock = s;
    s->selectCtx = selectCtx;

    np_tcp_socket* before = sockets->socketsSentinel.prev;
    np_tcp_socket* after = before->next;
    before->next = s;
    s->next = after;
    after->prev = s;
    s->prev = before;

    s->destroyed = false;
    s->aborted = false;
    return NABTO_EC_OK;
}

void destroy(np_tcp_socket* sock)
{
    if (sock == NULL) {
        return;
    }
    sock->destroyed = true;
    nm_select_unix_notify(sock->selectCtx);
    return;
}

np_error_code async_connect(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, np_tcp_connect_callback cb, void* userData)
{
    if (sock->aborted) {
        return NABTO_EC_ABORTED;
    }
    if (sock->connectCb) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    struct np_platform* pl = sock->pl;
    int s;

    int type = SOCK_STREAM;
#ifdef SOCK_NONBLOCK
    // Linux
    type |= SOCK_NONBLOCK;
#endif

    if (address->type == NABTO_IPV4) {
        s = socket(AF_INET, type, 0);
    } else if (address->type == NABTO_IPV6) {
        s = socket(AF_INET6, type, 0);
    } else {
        return NABTO_EC_NOT_SUPPORTED;
    }
    if (s < 0) {
        return NABTO_EC_FAILED;
    }

    sock->fd = s;

    int flags;
#ifndef SOCK_NONBLOCK
    // Mac
    flags = fcntl(sock->fd, F_GETFL, 0);
    if (flags < 0) {
        NABTO_LOG_ERROR(LOG, "cannot set nonblocking mode, fcntl F_GETFL failed");
        return NABTO_EC_FAILED;
    }
    if (fcntl(sock->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        NABTO_LOG_ERROR(LOG, "cannot set nonblocking mode, fcntl F_SETFL failed");
        return NABTO_EC_FAILED;
    }
#endif


    flags = 1;
    if (setsockopt(sock->fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flags, sizeof(int)) != 0) {
        NABTO_LOG_ERROR(LOG, "Could not set socket option TCP_NODELAY");
    }

    flags = 1;
    if(setsockopt(sock->fd, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags)) < 0) {
        NABTO_LOG_ERROR(LOG, "could not enable KEEPALIVE");
    }


#ifdef SOL_TCP
    // Linux
    flags = 9;
    if(setsockopt(sock->fd, SOL_TCP, TCP_KEEPCNT, &flags, sizeof(flags)) < 0) {
        NABTO_LOG_ERROR(LOG, "could not set TCP_KEEPCNT");
    }

    flags = 60;
    if(setsockopt(sock->fd, SOL_TCP, TCP_KEEPIDLE, &flags, sizeof(flags)) < 0) {
        NABTO_LOG_ERROR(LOG, "could not set TCP_KEEPIDLE");
    }

    flags = 60;
    if(setsockopt(sock->fd, SOL_TCP, TCP_KEEPINTVL, &flags, sizeof(flags)) < 0) {
        NABTO_LOG_ERROR(LOG, "could not set TCP KEEPINTVL");
    }
#endif


#if defined(SOL_SOCKET) && defined(SO_NOSIGPIPE)
    // Mac
    flags = 1;
    if (setsockopt(sock->fd, SOL_SOCKET, SO_NOSIGPIPE, (char *) &flags, sizeof(int)) != 0) {
        NABTO_LOG_ERROR(LOG, "Could not set socket option SO_NOSIGPIPE");
    }
#endif

#if defined(IPPROTO_TCP) && defined(TCP_KEEPALIVE)
    // Mac
    flags = 60;
    if(setsockopt(sock->fd, IPPROTO_TCP, TCP_KEEPALIVE, &flags, sizeof(flags)) < 0) {
        NABTO_LOG_ERROR(LOG, "could not set TCP_KEEPCNT");
    }
#endif

    {
        int status;
        if (address->type == NABTO_IPV4) {
            struct sockaddr_in host;

            memset(&host,0,sizeof(struct sockaddr_in));
            host.sin_family = AF_INET;
            memcpy((void*)&host.sin_addr, address->ip.v4, 4);
            host.sin_port = htons(port);
            status = connect(sock->fd, (struct sockaddr*)&host, sizeof(struct sockaddr_in));
        } else { // Must be ipv6 (address->type == NABTO_IPV6) {
            struct sockaddr_in6 host;

            memset(&host,0,sizeof(struct sockaddr_in6));
            host.sin6_family = AF_INET6;
            memcpy(host.sin6_addr.s6_addr, address->ip.v6, 16);
            host.sin6_port = htons(port);
            status = connect(sock->fd, (struct sockaddr*)&host, sizeof(struct sockaddr_in6));
        }
        if (status == 0) {
            // connected
            np_event_queue_post(pl, &sock->connectEvent, &is_connected, sock);
        } else {
            if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
                // OK
            } else {
                NABTO_LOG_ERROR(LOG, "Connect failed %s", strerror(errno));
                return NABTO_EC_FAILED;
            }
            nm_select_unix_notify(pl->tcpData);
        }

        // wait for the socket to be connected
        sock->connectCb = cb;
        sock->connectCbData = userData;
    }
    return NABTO_EC_OK;
}

void is_connected(void* userData)
{
    np_tcp_socket* sock = userData;
    if (sock->connectCb == NULL) {
        return;
    }
    int err;
    socklen_t len;
    len = sizeof(err);
    if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
        NABTO_LOG_ERROR(LOG, "getsockopt error %s",strerror(errno));
    } else {
        if (err == 0) {
            np_tcp_connect_callback cb = sock->connectCb;
            sock->connectCb = NULL;
            cb(NABTO_EC_OK, sock->connectCbData);
        } else if ( err == EINPROGRESS) {
            // Wait for next event
        } else {
            NABTO_LOG_ERROR(LOG, "Cannot connect socket %s", strerror(err));
            np_tcp_connect_callback cb = sock->connectCb;
            sock->connectCb = NULL;
            cb(NABTO_EC_FAILED, sock->connectCbData);
        }
    }
}

void tcp_do_write(np_tcp_socket* sock)
{
    if (sock->write.callback == NULL) {
        // nothing to write
        return;
    }
    int sent = send(sock->fd, sock->write.data, sock->write.dataLength, MSG_NOSIGNAL);
    if (sent < 0) {
        if (sent == EAGAIN || sent == EWOULDBLOCK) {
            // Wait for next event which triggers write.
            return;
        } else {
            np_tcp_write_callback cb = sock->write.callback;
            sock->write.callback = NULL;
            cb(NABTO_EC_FAILED, sock->write.userData);
            return;
        }
    } else {
        sock->write.data += sent;
        sock->write.dataLength -= sent;
        if (sock->write.dataLength > 0) {
            // Wait for next event which triggers write.
            return;
        } else {
            np_tcp_write_callback cb = sock->write.callback;
            sock->write.callback = NULL;
            cb(NABTO_EC_OK, sock->write.userData);
            return;
        }
    }
}

np_error_code async_write(np_tcp_socket* sock, const void* data, size_t dataLength, np_tcp_write_callback cb, void* userData)
{
    if (sock->aborted) {
        return NABTO_EC_ABORTED;
    }
    if (sock->write.callback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    sock->write.data = data;
    sock->write.dataLength = dataLength;
    sock->write.callback = cb;
    sock->write.userData = userData;

    nm_select_unix_notify(sock->selectCtx);
    return NABTO_EC_OK;
}

void tcp_do_read(np_tcp_socket* sock)
{
    if (sock->read.callback == NULL) {
        return;
    }
    int readen = recv(sock->fd, sock->read.buffer, sock->read.bufferSize, 0);
    if (readen == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // wait for next event.
            return;
        } else {
            NABTO_LOG_ERROR(LOG, "recv error %s", strerror(errno));
            np_tcp_read_callback cb = sock->read.callback;
            sock->read.callback = NULL;
            cb(NABTO_EC_FAILED, 0, sock->read.userData);
            return;
        }
    } else if (readen == 0) {
        np_tcp_read_callback cb = sock->read.callback;
        sock->read.callback = NULL;
        cb(NABTO_EC_EOF, 0, sock->read.userData);
        return;
    } else {
        np_tcp_read_callback cb = sock->read.callback;
        sock->read.callback = NULL;
        cb(NABTO_EC_OK, readen, sock->read.userData);
        return;
    }
}


np_error_code async_read(np_tcp_socket* sock, void* buffer, size_t bufferSize, np_tcp_read_callback cb, void* userData)
{
    if (sock->aborted) {
        return NABTO_EC_ABORTED;
    }
    if (sock->read.callback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    sock->read.buffer = buffer;
    sock->read.bufferSize = bufferSize;
    sock->read.callback = cb;
    sock->read.userData = userData;
    nm_select_unix_notify(sock->selectCtx);
    return NABTO_EC_OK;
}

np_error_code tcp_shutdown(np_tcp_socket* sock)
{
    shutdown(sock->fd, SHUT_WR);
    return NABTO_EC_OK;
}

void nm_select_unix_tcp_event_abort(void* userData)
{
    np_tcp_socket* sock = (np_tcp_socket*)userData;
    if (sock->read.callback != NULL) {
        np_tcp_read_callback cb = sock->read.callback;
        sock->read.callback = NULL;
        cb(NABTO_EC_ABORTED, 0, sock->read.userData);
    }
    if (sock->write.callback != NULL) {
        np_tcp_write_callback cb = sock->write.callback;
        sock->write.callback = NULL;
        cb(NABTO_EC_ABORTED, sock->write.userData);
    }
    if (sock->connectCb) {
        np_tcp_connect_callback cb = sock->connectCb;
        sock->connectCb = NULL;
        cb(NABTO_EC_ABORTED, sock->connectCbData);
    }
}

np_error_code tcp_close(np_tcp_socket* sock)
{
    if (sock->aborted) {
        return NABTO_EC_OK;
    }
    sock->aborted = true;
    np_event_queue_post(sock->pl, &sock->abortEv, &nm_select_unix_tcp_event_abort, sock);
    return NABTO_EC_OK;
}
