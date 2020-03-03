#include "nm_epoll_tcp.h"

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

struct nm_tcp_write_context {
    const void* data;
    size_t dataLength;
    np_tcp_write_callback callback;
    void* userData;
    struct np_event event;
};

struct nm_tcp_read_context {
    void* buffer;
    size_t bufferSize;
    np_tcp_read_callback callback;
    void* userData;
    struct np_event event;
};

struct nm_tcp_connect_context {
    np_tcp_connect_callback callback;
    void* userData;
    struct np_event event;
};

struct np_tcp_socket {
    enum nm_epoll_type type;
    struct nm_epoll_base* next;
    struct nm_epoll_base* prev;
    struct nm_epoll_context* epoll;
    struct np_platform* pl;
    int fd;
    struct nm_tcp_write_context write;
    struct nm_tcp_read_context read;
    struct nm_tcp_connect_context connect;
    bool aborted;
    struct np_event abortEv;
};

static np_error_code nm_epoll_tcp_create(struct np_platform* pl, np_tcp_socket** sock);
static void nm_epoll_tcp_destroy(np_tcp_socket* sock);
static np_error_code nm_epoll_tcp_async_connect(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, np_tcp_connect_callback, void* userData);
static np_error_code nm_epoll_tcp_async_write(np_tcp_socket* sock, const void* data, size_t dataLength, np_tcp_write_callback cb, void* userData);
static np_error_code nm_epoll_tcp_async_read(np_tcp_socket* sock, void* buffer, size_t bufferLength, np_tcp_read_callback cb, void* userData);
static np_error_code nm_epoll_tcp_shutdown(np_tcp_socket* sock);
static np_error_code nm_epoll_tcp_abort(np_tcp_socket* sock);


static void nm_epoll_tcp_is_connected(void* userData);

void nm_epoll_tcp_init(struct nm_epoll_context* epoll, struct np_platform* pl)
{
    pl->tcp.create = &nm_epoll_tcp_create;
    pl->tcp.destroy = &nm_epoll_tcp_destroy;
    pl->tcp.async_connect = &nm_epoll_tcp_async_connect;
    pl->tcp.async_write = &nm_epoll_tcp_async_write;
    pl->tcp.async_read = &nm_epoll_tcp_async_read;
    pl->tcp.shutdown = &nm_epoll_tcp_shutdown;
    pl->tcp.abort = &nm_epoll_tcp_abort;
    pl->tcpData = epoll;
}

np_error_code nm_epoll_tcp_create(struct np_platform* pl, np_tcp_socket** sock)
{
    np_tcp_socket* s = calloc(1,sizeof(struct np_tcp_socket));
    if (s == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    s->type = NM_EPOLL_TYPE_TCP;
    s->pl = pl;
    s->epoll = (struct nm_epoll_context*)pl->tcpData;
    s->fd = -1;
    s->aborted = false;
    *sock = s;

    nm_epoll_add_tcp_socket(s->epoll);
    np_event_queue_init_event(&s->write.event);
    np_event_queue_init_event(&s->read.event);
    np_event_queue_init_event(&s->connect.event);
    return NABTO_EC_OK;
}

void nm_epoll_tcp_destroy(np_tcp_socket* sock)
{
    nm_epoll_close_socket(sock->pl->tcpData, (struct nm_epoll_base*)sock);
    nm_epoll_break_wait(sock->pl->tcpData);
}

np_error_code nm_epoll_tcp_async_connect(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, np_tcp_connect_callback cb, void* userData)
{
    if (sock->connect.callback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    if (sock->aborted) {
        return NABTO_EC_ABORTED;
    }

    struct np_platform* pl = sock->pl;
    int s;
    if (address->type == NABTO_IPV4) {
        s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    } else if (address->type == NABTO_IPV6) {
        s = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    } else {
        return NABTO_EC_NOT_SUPPORTED;
    }
    if (s < 0) {
        return NABTO_EC_UNKNOWN;
    }

    sock->fd = s;
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.ptr = sock;
    epoll_ctl(sock->epoll->fd, EPOLL_CTL_ADD, sock->fd, &ev);

    {
        int flags = 1;
        if (setsockopt(sock->fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flags, sizeof(int)) != 0) {
            NABTO_LOG_ERROR(LOG, "Could not set socket option TCP_NODELAY");
        }

        flags = 1;
        if(setsockopt(sock->fd, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags)) < 0) {
            NABTO_LOG_ERROR(LOG, "could not enable KEEPALIVE");
        }

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

    }
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
            np_event_queue_post(pl, &sock->connect.event, &nm_epoll_tcp_is_connected, sock);
        } else if (status != 0 && errno != EINPROGRESS) {
            NABTO_LOG_ERROR(LOG, "Connect failed %s", strerror(errno));
            return NABTO_EC_UNKNOWN;
        }

        // wait for the socket to be connected
        sock->connect.callback = cb;
        sock->connect.userData = userData;
    }
    return NABTO_EC_OK;
}

/**
 * This function may only be called upon a EPOLLOUT event
 */
void nm_epoll_tcp_is_connected(void* userData)
{
    np_tcp_socket* sock = userData;
    if (sock->connect.callback == NULL)  {
        return;
    }
    int err;
    socklen_t len;
    len = sizeof(err);
    if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
        NABTO_LOG_ERROR(LOG, "getsockopt error %s",strerror(errno));
    } else {
        if (err == 0) {
            np_tcp_connect_callback cb = sock->connect.callback;
            sock->connect.callback = NULL;
            cb(NABTO_EC_OK, sock->connect.userData);
        } else if ( err == EINPROGRESS) {
            // Wait for next event
        } else {
            NABTO_LOG_ERROR(LOG, "Cannot connect socket %s", strerror(err));
            np_tcp_connect_callback cb = sock->connect.callback;
            sock->connect.callback = NULL;
            cb(NABTO_EC_UNKNOWN, sock->connect.userData);
        }
    }
}

void nm_epoll_tcp_do_write(void* data)
{
    np_tcp_socket* sock = data;
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
            cb(NABTO_EC_UNKNOWN, sock->write.userData);
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
            np_event_queue_cancel_event(sock->pl, &sock->write.event); // just an optimization
            cb(NABTO_EC_OK, sock->write.userData);
            return;
        }
    }
}

np_error_code nm_epoll_tcp_async_write(np_tcp_socket* sock, const void* data, size_t dataLength, np_tcp_write_callback cb, void* userData)
{
    if (sock->write.callback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    if (sock->aborted) {
        return NABTO_EC_ABORTED;
    }
    sock->write.data = data;
    sock->write.dataLength = dataLength;
    sock->write.callback = cb;
    sock->write.userData = userData;

    // the event can be completed by epoll or by the event queue
    np_event_queue_post_maybe_double(sock->pl, &sock->write.event, &nm_epoll_tcp_do_write, sock);

    return NABTO_EC_OK;
}

void nm_epoll_tcp_do_read(void* userData)
{
    np_tcp_socket* sock = userData;
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
            cb(NABTO_EC_UNKNOWN, 0, sock->read.userData);
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
        np_event_queue_cancel_event(sock->pl, &sock->read.event); // just an optimization
        cb(NABTO_EC_OK, readen, sock->read.userData);
        return;
    }
}

np_error_code nm_epoll_tcp_async_read(np_tcp_socket* sock, void* buffer, size_t bufferSize, np_tcp_read_callback cb, void* userData)
{
    if (sock->read.callback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    if (sock->aborted) {
        return NABTO_EC_ABORTED;
    }
    sock->read.buffer = buffer;
    sock->read.bufferSize = bufferSize;
    sock->read.callback = cb;
    sock->read.userData = userData;
    np_event_queue_post_maybe_double(sock->pl, &sock->read.event, &nm_epoll_tcp_do_read, sock);
    return NABTO_EC_OK;
}

np_error_code nm_epoll_tcp_shutdown(np_tcp_socket* sock)
{
    if (sock->aborted) {
        return NABTO_EC_ABORTED;
    }
    shutdown(sock->fd, SHUT_WR);
    return NABTO_EC_OK;
}

void nm_epoll_tcp_cancel_all_events(np_tcp_socket* sock)
{
    NABTO_LOG_TRACE(LOG, "Cancelling all events");
    np_event_queue_cancel_event(sock->pl, &sock->abortEv);
    np_event_queue_cancel_event(sock->pl, &sock->write.event);
    np_event_queue_cancel_event(sock->pl, &sock->read.event);
    np_event_queue_cancel_event(sock->pl, &sock->connect.event);
}

void nm_epoll_tcp_resolve_close(struct nm_epoll_base* base)
{
    np_tcp_socket* sock = (np_tcp_socket*)base;
    close(sock->fd);
    shutdown(sock->fd, SHUT_RDWR);
    epoll_ctl(sock->epoll->fd, EPOLL_CTL_DEL, sock->fd, NULL);
    sock->fd = -1;
    nm_epoll_tcp_cancel_all_events(sock);
    nm_epoll_remove_tcp_socket(sock->epoll);
    free(sock);
}

void nm_epoll_tcp_event_abort(void* userData)
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
    if (sock->connect.callback) {
        np_tcp_connect_callback cb = sock->connect.callback;
        sock->connect.callback = NULL;
        cb(NABTO_EC_ABORTED, sock->connect.userData);
    }
}

np_error_code nm_epoll_tcp_abort(np_tcp_socket* sock)
{
    if (sock->aborted) {
        return NABTO_EC_OK;
    }
    sock->aborted = true;
    np_event_queue_post(sock->pl, &sock->abortEv, &nm_epoll_tcp_event_abort, sock);
    return NABTO_EC_OK;
}


void nm_epoll_tcp_handle_event(np_tcp_socket* sock, uint32_t events)
{
    if (events & EPOLLOUT) {
        nm_epoll_tcp_is_connected(sock);
        np_event_queue_post_maybe_double(sock->pl, &sock->write.event, &nm_epoll_tcp_do_write, sock);
        //nm_epoll_tcp_do_write(sock);
    }
    if (events & EPOLLIN) {
        np_event_queue_post_maybe_double(sock->pl, &sock->read.event, &nm_epoll_tcp_do_read, sock);
        //nm_epoll_tcp_do_read(sock);
    }
}
