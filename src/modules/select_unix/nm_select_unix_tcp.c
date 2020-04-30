#include "nm_select_unix_tcp.h"

#include <platform/np_util.h>
#include <platform/np_logging.h>
#include <platform/np_completion_event.h>

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
static void async_connect(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, struct np_completion_event* completionEvent);
static void async_write(np_tcp_socket* sock, const void* data, size_t dataLength, struct np_completion_event* completionEvent);
static void async_read(np_tcp_socket* sock, void* buffer, size_t bufferLength, size_t* readLength, struct np_completion_event* completionEvent);
static np_error_code tcp_shutdown(np_tcp_socket* sock);
static void tcp_abort(np_tcp_socket* sock);

static void is_connected(np_tcp_socket* sock);
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
    pl->tcp.abort = &tcp_abort;
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
        if (iterator->read.completionEvent != NULL) {
            FD_SET(iterator->fd, &ctx->readFds);
            ctx->maxReadFd = NP_MAX(ctx->maxReadFd, iterator->fd);
        }
        if (iterator->write.completionEvent != NULL || iterator->connect.completionEvent != NULL) {
            FD_SET(iterator->fd, &ctx->writeFds);
            ctx->maxWriteFd = NP_MAX(ctx->maxWriteFd, iterator->fd);
        }
        iterator = iterator->next;
    }
}

void nm_select_unix_tcp_free_socket(struct np_tcp_socket* sock)
{
    np_tcp_socket* before = sock->prev;
    np_tcp_socket* after = sock->next;
    before->next = after;
    after->prev = before;

    tcp_abort(sock);
    shutdown(sock->fd, SHUT_RDWR);
    close(sock->fd);
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
            if (iterator->connect.completionEvent) {
                is_connected(iterator);
            }
            if (iterator->write.completionEvent) {
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

np_error_code async_connect_ec(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port)
{
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
        return NABTO_EC_UNKNOWN;
    }

    sock->fd = s;

    int flags;
#ifndef SOCK_NONBLOCK
    // Mac
    flags = fcntl(sock->fd, F_GETFL, 0);
    if (flags < 0) {
        NABTO_LOG_ERROR(LOG, "cannot set nonblocking mode, fcntl F_GETFL failed");
        return NABTO_EC_UNKNOWN;
    }
    if (fcntl(sock->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        NABTO_LOG_ERROR(LOG, "cannot set nonblocking mode, fcntl F_SETFL failed");
        return NABTO_EC_UNKNOWN;
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
            return NABTO_EC_OK;
        } else {
            if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
                // OK
            } else {
                NABTO_LOG_ERROR(LOG, "Connect failed %s", strerror(errno));
                return NABTO_EC_UNKNOWN;
            }
            nm_select_unix_notify(pl->tcpData);
        }
    }
    return NABTO_EC_AGAIN;
}

void async_connect(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, struct np_completion_event* completionEvent)
{
    if (sock->aborted) {
        np_completion_event_resolve(completionEvent, NABTO_EC_ABORTED);
        return;
    }
    if (sock->connect.completionEvent) {
        np_completion_event_resolve(completionEvent, NABTO_EC_OPERATION_IN_PROGRESS);
        return;
    }


    sock->connect.completionEvent = completionEvent;
    np_error_code ec = async_connect_ec(sock, address, port);
    if (ec == NABTO_EC_AGAIN) {
        // a deferred operation has begun
        return;
    } else {
        // connected or error.
        sock->connect.completionEvent = NULL;
        np_completion_event_resolve(completionEvent, ec);
        return;
    }
}

np_error_code is_connected_ec(np_tcp_socket* sock)
{
    int err;
    socklen_t len;
    len = sizeof(err);
    if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
        NABTO_LOG_ERROR(LOG, "getsockopt error %s",strerror(errno));
        return NABTO_EC_UNKNOWN;
    } else {
        if (err == 0) {
            return NABTO_EC_OK;
        } else if ( err == EINPROGRESS) {
            // Wait for next event
            return NABTO_EC_AGAIN;
        } else {
            NABTO_LOG_ERROR(LOG, "Cannot connect socket %s", strerror(err));
            return NABTO_EC_UNKNOWN;
        }
    }
}

void is_connected(np_tcp_socket* sock) {
    if (sock->connect.completionEvent == NULL) {
        return;
    }

    np_error_code ec = is_connected_ec(sock);
    if (ec != NABTO_EC_AGAIN) {
        struct np_completion_event* ev = sock->connect.completionEvent;
        sock->connect.completionEvent = NULL;
        np_completion_event_resolve(ev, ec);
    }
}

np_error_code tcp_do_write_ec(np_tcp_socket* sock)
{
    int sent = send(sock->fd, sock->write.data, sock->write.dataLength, MSG_NOSIGNAL);
    if (sent < 0) {
        if (sent == EAGAIN || sent == EWOULDBLOCK) {
            // Wait for next event which triggers write.
            return NABTO_EC_AGAIN;
        } else {
            return NABTO_EC_UNKNOWN;
        }
    } else {
        sock->write.data += sent;
        sock->write.dataLength -= sent;
        if (sock->write.dataLength > 0) {
            // Wait for next event which triggers write.
            return NABTO_EC_AGAIN;
        } else {
            return NABTO_EC_OK;
        }
    }
}

void tcp_do_write(np_tcp_socket* sock)
{
    if (sock->write.completionEvent == NULL) {
        // nothing to write
        return;
    }

    np_error_code ec = tcp_do_write_ec(sock);
    if (ec != NABTO_EC_AGAIN) {
        struct np_completion_event* ev = sock->write.completionEvent;
        sock->write.completionEvent = NULL;
        np_completion_event_resolve(ev, ec);
    }
}

np_error_code async_write_ec(np_tcp_socket* sock, const void* data, size_t dataLength)

{
    sock->write.data = data;
    sock->write.dataLength = dataLength;

    nm_select_unix_notify(sock->selectCtx);
    return NABTO_EC_AGAIN;
}

void async_write(np_tcp_socket* sock, const void* data, size_t dataLength, struct np_completion_event* completionEvent)
{
    if (sock->aborted) {
        np_completion_event_resolve(completionEvent, NABTO_EC_ABORTED);
        return;
    }
    if (sock->write.completionEvent != NULL) {
        np_completion_event_resolve(completionEvent, NABTO_EC_OPERATION_IN_PROGRESS);
        return;
    }

    sock->write.completionEvent = completionEvent;

    np_error_code ec = async_write_ec(sock, data, dataLength);
    if (ec != NABTO_EC_AGAIN) {
        sock->write.completionEvent = NULL;
        np_completion_event_resolve(completionEvent, ec);
    }
}

np_error_code tcp_do_read_ec(np_tcp_socket* sock)
{
    int readen = recv(sock->fd, sock->read.buffer, sock->read.bufferSize, 0);
    if (readen == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return NABTO_EC_AGAIN;
        } else {
            NABTO_LOG_ERROR(LOG, "recv error %s", strerror(errno));
            return NABTO_EC_UNKNOWN;
        }
    } else if (readen == 0) {
        return NABTO_EC_EOF;
    } else {
        *(sock->read.readLength) = readen;
        return NABTO_EC_OK;
    }
}

void tcp_do_read(np_tcp_socket* sock)
{
    if (sock->read.completionEvent == NULL) {
        return;
    }

    np_error_code ec = tcp_do_read_ec(sock);

    if (ec != NABTO_EC_AGAIN) {
        struct np_completion_event* ev = sock->read.completionEvent;
        sock->read.completionEvent = NULL;
        np_completion_event_resolve(ev, ec);
    }
}


void async_read(np_tcp_socket* sock, void* buffer, size_t bufferSize, size_t* readLength, struct np_completion_event* completionEvent)
{
    if (sock->aborted) {
        np_completion_event_resolve(completionEvent, NABTO_EC_ABORTED);
        return;
    }
    if (sock->read.completionEvent != NULL) {
        np_completion_event_resolve(completionEvent, NABTO_EC_OPERATION_IN_PROGRESS);
        return;
    }
    sock->read.buffer = buffer;
    sock->read.bufferSize = bufferSize;
    sock->read.readLength = readLength;
    sock->read.completionEvent = completionEvent;
    nm_select_unix_notify(sock->selectCtx);
}

np_error_code tcp_shutdown(np_tcp_socket* sock)
{
    shutdown(sock->fd, SHUT_WR);
    return NABTO_EC_OK;
}

void tcp_abort(np_tcp_socket* sock)
{
    if (sock->aborted) {
        return;
    }
    sock->aborted = true;
    if (sock->read.completionEvent != NULL) {
        struct np_completion_event* ev = sock->read.completionEvent;
        sock->read.completionEvent = NULL;
        np_completion_event_resolve(ev, NABTO_EC_ABORTED);
    }
    if (sock->write.completionEvent != NULL) {
        struct np_completion_event* ev = sock->write.completionEvent;
        sock->write.completionEvent = NULL;
        np_completion_event_resolve(ev, NABTO_EC_ABORTED);
    }
    if (sock->connect.completionEvent) {
        struct np_completion_event* ev = sock->connect.completionEvent;
        sock->connect.completionEvent = NULL;
        np_completion_event_resolve(ev, NABTO_EC_ABORTED);
    }
}
