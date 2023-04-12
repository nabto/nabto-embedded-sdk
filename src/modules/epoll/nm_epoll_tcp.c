#include "nm_epoll.h"

#include <platform/np_util.h>
#include <platform/np_logging.h>
#include <platform/np_completion_event.h>
#include <platform/np_allocator.h>
#include <platform/interfaces/np_tcp.h>



#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

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
static void update_epoll(struct np_tcp_socket* sock);

static struct np_tcp_functions module = {
    .create = &create,
    .destroy = &destroy,
    .async_connect = &async_connect,
    .async_write = &async_write,
    .async_read = &async_read,
    .shutdown = &tcp_shutdown,
    .abort = &tcp_abort
};

struct np_tcp nm_epoll_tcp_get_impl(struct nm_epoll* ctx)
{
    struct np_tcp obj;
    obj.mptr = &module;
    obj.data = ctx;
    return obj;
}


void nm_epoll_tcp_free_socket(struct np_tcp_socket* sock)
{

    tcp_abort(sock);
    if (sock->fd != -1) {
        shutdown(sock->fd, SHUT_RDWR);
        close(sock->fd);
        epoll_ctl(sock->ctx->epollFd, EPOLL_CTL_DEL, sock->fd, &sock->epollEvent);
        sock->fd = -1;
    }
    np_free(sock);

}

void nm_epoll_tcp_handle_event(struct np_tcp_socket* sock, uint32_t events) 
{
    is_connected(sock);
    if (events & EPOLLIN) {
        tcp_do_read(sock);
    }
    if (events & EPOLLOUT) {
        tcp_do_write(sock);
    }
}

np_error_code create(struct np_tcp* obj, struct np_tcp_socket** sock)
{
    struct nm_epoll* epollCtx = obj->data;
    struct np_tcp_socket* s = np_calloc(1,sizeof(struct np_tcp_socket));
    if (s == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    s->fd = -1;
    *sock = s;
    s->ctx = epollCtx;
    s->aborted = false;
    s->epollType = NM_EPOLL_TYPE_TCP;
    return NABTO_EC_OK;
}

void destroy(struct np_tcp_socket* sock)
{
    if (sock == NULL) {
        return;
    }
    nm_epoll_tcp_free_socket(sock);
    return;
}

static np_error_code async_connect_ec(struct np_tcp_socket* sock, struct np_ip_address* address, uint16_t port)
{
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
    sock->epollEvent.data.ptr = sock;
    epoll_ctl(sock->ctx->epollFd, EPOLL_CTL_ADD, sock->fd, &sock->epollEvent);

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
            // TODO add to epoll
        }
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
        update_epoll(sock);
        // a deferred operation has begun
        return;
    } else {
        // connected or error.
        sock->connect.completionEvent = NULL;
        np_completion_event_resolve(completionEvent, ec);
        return;
    }
}

static np_error_code is_connected_ec(struct np_tcp_socket* sock)
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
        } else if ( err == ECONNREFUSED) {
            return NABTO_EC_ABORTED;
        } else {
            NABTO_LOG_ERROR(LOG, "Cannot connect socket %s", strerror(err));
            return NABTO_EC_UNKNOWN;
        }
    }
}

void is_connected(struct np_tcp_socket* sock) {
    if (sock->connect.completionEvent == NULL) {
        return;
    }

    np_error_code ec = is_connected_ec(sock);
    if (ec != NABTO_EC_AGAIN) {
        struct np_completion_event* ev = sock->connect.completionEvent;
        sock->connect.completionEvent = NULL;
        update_epoll(sock);
        np_completion_event_resolve(ev, ec);
    }
}

static np_error_code tcp_do_write_ec(struct np_tcp_socket* sock)
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
        sock->write.data = (uint8_t*)sock->write.data + sent;
        sock->write.dataLength -= sent;
        if (sock->write.dataLength > 0) {
            // Wait for next event which triggers write.
            return NABTO_EC_AGAIN;
        } else {
            return NABTO_EC_OK;
        }
    }
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
        update_epoll(sock);
        np_completion_event_resolve(ev, ec);
    } else {
        // TODO add to epoll set.
    }
}

static np_error_code async_write_ec(struct np_tcp_socket* sock, const void* data, size_t dataLength)

{
    sock->write.data = data;
    sock->write.dataLength = dataLength;

    // TODO inform epoll
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
    } else {
        update_epoll(sock);
    }
}

static np_error_code tcp_do_read_ec(struct np_tcp_socket* sock)
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

void tcp_do_read(struct np_tcp_socket* sock)
{
    if (sock->read.completionEvent == NULL) {
        return;
    }

    np_error_code ec = tcp_do_read_ec(sock);

    if (ec != NABTO_EC_AGAIN) {
        struct np_completion_event* ev = sock->read.completionEvent;
        sock->read.completionEvent = NULL;
        update_epoll(sock);
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
    update_epoll(sock);
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
    update_epoll(sock);
}

void update_epoll(struct np_tcp_socket* sock) {
    //NABTO_LOG_INFO(LOG, "Updating epoll %d, epoll fd %d", sock->fd, sock->ctx->epollFd);
    if (sock->fd == -1) {
        return;
    }
    sock->epollEvent.events = 0;
    if (sock->connect.completionEvent != NULL) {
        sock->epollEvent.events |= EPOLLOUT;
    }
    if (sock->read.completionEvent != NULL) {
        sock->epollEvent.events |= EPOLLIN;
    }
    if (sock->write.completionEvent != NULL) {
        sock->epollEvent.events |= EPOLLOUT;
    }
    int ec = epoll_ctl(sock->ctx->epollFd, EPOLL_CTL_MOD, sock->fd, &sock->epollEvent);
    if (ec == -1) {
        NABTO_LOG_ERROR(LOG, "Cannot update epoll %d, %s", sock->fd, strerror(errno));
    }
}
