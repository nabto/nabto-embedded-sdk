#include "nm_select_unix_tcp.h"

#include <platform/np_allocator.h>
#include <platform/np_completion_event.h>
#include <platform/np_logging.h>
#include <platform/np_util.h>



#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netinet/tcp.h>

#define LOG NABTO_LOG_MODULE_TCP

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static np_error_code create(struct np_tcp* obj, struct np_tcp_socket** sock);
static void destroy(struct np_tcp_socket* sock);
static void async_connect(struct np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, struct np_completion_event* completionEvent);
static void async_write(struct np_tcp_socket* sock, const void* data, size_t dataLength, struct np_completion_event* completionEvent);
static void async_read(struct np_tcp_socket* sock, void* buffer, size_t bufferLength, size_t* readLength, struct np_completion_event* completionEvent);
static void tcp_shutdown(struct np_tcp_socket* sock);
static void tcp_abort(struct np_tcp_socket* sock);

static void is_connected(struct np_tcp_socket* sock);
static void tcp_do_write(struct np_tcp_socket* sock);
static void tcp_do_read(struct np_tcp_socket* sock);

static struct np_tcp_functions module = {
    .create = &create,
    .destroy = &destroy,
    .async_connect = &async_connect,
    .async_write = &async_write,
    .async_read = &async_read,
    .shutdown = &tcp_shutdown,
    .abort = &tcp_abort
};

struct np_tcp nm_select_unix_tcp_get_impl(struct nm_select_unix* ctx)
{
    struct np_tcp obj;
    obj.mptr = &module;
    obj.data = ctx;
    return obj;
}

void nm_select_unix_tcp_build_fd_sets(struct nm_select_unix* ctx)
{
    struct np_tcp_socket* s = NULL;
    nm_select_unix_lock(ctx);
    NN_LLIST_FOREACH(s, &ctx->tcpSockets)
    {
        if (s->read.completionEvent != NULL) {
            FD_SET(s->fd, &ctx->readFds);
            ctx->maxReadFd = NP_MAX(ctx->maxReadFd, s->fd);
        }
        if (s->write.completionEvent != NULL || s->connect.completionEvent != NULL) {
            FD_SET(s->fd, &ctx->writeFds);
            ctx->maxWriteFd = NP_MAX(ctx->maxWriteFd, s->fd);
        }
    }
    nm_select_unix_unlock(ctx);
}

void nm_select_unix_tcp_free_socket(struct np_tcp_socket* sock)
{
    nm_select_unix_lock(sock->selectCtx);
    nn_llist_erase_node(&sock->tcpSocketsNode);
    nm_select_unix_unlock(sock->selectCtx);

    tcp_abort(sock);
    shutdown(sock->fd, SHUT_RDWR);
    close(sock->fd);
    np_free(sock);

}

void nm_select_unix_tcp_handle_select(struct nm_select_unix* ctx, int nfds)
{
    (void)nfds;
    struct np_tcp_socket* s = NULL;
    nm_select_unix_lock(ctx);
    NN_LLIST_FOREACH(s, &ctx->tcpSockets)
    {
        if (FD_ISSET(s->fd, &ctx->readFds)) {
            tcp_do_read(s);
        }
        if (FD_ISSET(s->fd, &ctx->writeFds)) {
            if (s->connect.completionEvent) {
                is_connected(s);
            }
            if (s->write.completionEvent) {
                tcp_do_write(s);
            }
        }
    }
    nm_select_unix_unlock(ctx);
}


np_error_code create(struct np_tcp* obj, struct np_tcp_socket** sock)
{
    struct nm_select_unix* selectCtx = obj->data;
    struct np_tcp_socket* s = np_calloc(1,sizeof(struct np_tcp_socket));
    if (s == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    s->fd = NM_SELECT_UNIX_INVALID_SOCKET;
    *sock = s;
    s->selectCtx = selectCtx;
    nm_select_unix_lock(selectCtx);
    nn_llist_append(&selectCtx->tcpSockets, &s->tcpSocketsNode, s);
    nm_select_unix_unlock(selectCtx);
    s->aborted = false;
    return NABTO_EC_OK;
}

void destroy(struct np_tcp_socket* sock)
{
    if (sock == NULL) {
        return;
    }
    nm_select_unix_tcp_free_socket(sock);
    return;
}

np_error_code async_connect_ec(struct np_tcp_socket* sock, struct np_ip_address* address, uint16_t port)
{
    int s = 0;

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

    int flags = 0;
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
        int status = 0;
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
        }
        if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
            // OK
        } else {
            NABTO_LOG_ERROR(LOG, "Connect failed %s", strerror(errno));
            return NABTO_EC_UNKNOWN;
        }
        nm_select_unix_notify(sock->selectCtx);
    }
    return NABTO_EC_AGAIN;
}

void async_connect(struct np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, struct np_completion_event* completionEvent)
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
    }
    // connected or error.
    sock->connect.completionEvent = NULL;
    np_completion_event_resolve(completionEvent, ec);
    return;
}

np_error_code is_connected_ec(struct np_tcp_socket* sock)
{
    int err = 0;
    socklen_t len = 0;
    len = sizeof(err);
    if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
        NABTO_LOG_ERROR(LOG, "getsockopt error %s",strerror(errno));
        return NABTO_EC_UNKNOWN;
    }
    if (err == 0) {
        return NABTO_EC_OK;
    }
    if ( err == EINPROGRESS) {
        // Wait for next event
        return NABTO_EC_AGAIN;
    }
    if (err == ECONNREFUSED) {
        NABTO_LOG_TRACE(LOG, "Cannot connect socket %s", strerror(err));
        return NABTO_EC_ABORTED;
    }
    NABTO_LOG_ERROR(LOG, "Cannot connect socket %s", strerror(err));
    return NABTO_EC_UNKNOWN;
}

void is_connected(struct np_tcp_socket* sock) {
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

np_error_code tcp_do_write_ec(struct np_tcp_socket* sock)
{
    ssize_t sent = send(sock->fd, sock->write.data, sock->write.dataLength, MSG_NOSIGNAL);
    if (sent < 0) {
        int err = errno;
        if (err == EAGAIN || err == EWOULDBLOCK) {
            // Wait for next event which triggers write.
            return NABTO_EC_AGAIN;
        }
        NABTO_LOG_TRACE(LOG, "TCP send failed '%s'", strerror(err));
        return NABTO_EC_FAILED;
    }
    sock->write.data = (uint8_t*)sock->write.data + sent;
    sock->write.dataLength -= sent;
    if (sock->write.dataLength > 0) {
        // Wait for next event which triggers write.
        return NABTO_EC_AGAIN;
    }
    return NABTO_EC_OK;
}

void tcp_do_write(struct np_tcp_socket* sock)
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

np_error_code async_write_ec(struct np_tcp_socket* sock, const void* data, size_t dataLength)

{
    sock->write.data = data;
    sock->write.dataLength = dataLength;

    nm_select_unix_notify(sock->selectCtx);
    return NABTO_EC_AGAIN;
}

void async_write(struct np_tcp_socket* sock, const void* data, size_t dataLength, struct np_completion_event* completionEvent)
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

np_error_code tcp_do_read_ec(struct np_tcp_socket* sock)
{
    ssize_t readen = recv(sock->fd, sock->read.buffer, sock->read.bufferSize, 0);
    if (readen < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return NABTO_EC_AGAIN;
        }
        NABTO_LOG_ERROR(LOG, "recv error %s", strerror(errno));
        return NABTO_EC_FAILED;
    }
    if (readen == 0) {
        return NABTO_EC_EOF;
    }
    *(sock->read.readLength) = readen;
    return NABTO_EC_OK;
}

void tcp_do_read(struct np_tcp_socket* sock)
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


void async_read(struct np_tcp_socket* sock, void* buffer, size_t bufferSize, size_t* readLength, struct np_completion_event* completionEvent)
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

void tcp_shutdown(struct np_tcp_socket* sock)
{
    shutdown(sock->fd, SHUT_WR);
}

void tcp_abort(struct np_tcp_socket* sock)
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
