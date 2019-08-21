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
    struct nm_epoll_context* epoll;
    struct np_platform* pl;
    int fd;
    struct nm_tcp_write_context write;
    struct nm_tcp_read_context read;
    struct nm_tcp_connect_context connect;
};

static np_error_code nm_tcp_epoll_create(struct np_platform* pl, np_tcp_socket** sock);
static void nm_tcp_epoll_destroy(np_tcp_socket* sock);
static np_error_code nm_tcp_epoll_async_connect(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, np_tcp_connect_callback, void* userData);
static np_error_code nm_tcp_epoll_async_write(np_tcp_socket* sock, const void* data, size_t dataLength, np_tcp_write_callback cb, void* userData);
static np_error_code nm_tcp_epoll_async_read(np_tcp_socket* sock, const void* buffer, size_t bufferLength, np_tcp_read_callback cb, void* userData);
static np_error_code nm_tcp_epoll_shutdown(np_tcp_socket* sock);
static np_error_code nm_tcp_epoll_close(np_tcp_socket* sock);


void nm_tcp_epoll_init(struct nm_epoll_context* epoll, struct np_platform* pl)
{
    pl->tcp.create = &nm_tcp_epoll_create;
    pl->tcp.destroy = &nm_tcp_epoll_destroy;
    pl->tcp.async_connect = &nm_tcp_epoll_async_connect;
    pl->tcp.async_write = &nm_tcp_epoll_async_write;
    pl->tcp.async_read = &nm_tcp_epoll_async_read;
    pl->tcp.shutdown = &nm_tcp_epoll_shutdown;
    pl->tcp.close = &nm_tcp_epoll_close;
    pl->tcpData = epoll;
}

np_error_code nm_tcp_epoll_create(struct np_platform* pl, np_tcp_socket** sock)
{

    np_tcp_socket* s = calloc(1,sizeof(struct np_tcp_socket));
    s->pl = pl;
    s->epoll = (struct nm_epoll_context*)pl->tcpData;
    s->fd = -1;
    *sock = s;
    return NABTO_EC_OK;
}

void nm_tcp_epoll_destroy(np_tcp_socket* sock)
{
    if (sock->fd != -1) {
        close(sock->fd);
        shutdown(sock->fd, SHUT_RDWR);
        epoll_ctl(sock->epoll->fd, EPOLL_CTL_DEL, sock->fd, NULL);
        sock->fd = -1;
    }
    free(sock);
}

np_error_code nm_tcp_epoll_async_connect(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, np_tcp_connect_callback cb, void* userData)
{
    if (sock->connect.callback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    int s;
    if (address->type == NABTO_IPV4) {
        s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    } else if (address->type == NABTO_IPV6) {
        s = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    } else {
        return NABTO_EC_NOT_SUPPORTED;
    }
    if (s < 0) {
        return NABTO_EC_FAILED;
    }

    sock->fd = s;
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
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
            memcpy((void*)&host.sin_addr, address->v4.addr, 4);
            host.sin_port = htons(port);
            //NABTO_LOG_TRACE(LOG, "Connecting to ", PRIep, MAKE_EP_PRINTABLE(*ep));

            status = connect(sock->fd, (struct sockaddr*)&host, sizeof(struct sockaddr_in));
        } else { // Must be ipv6 (address->type == NABTO_IPV6) {
            struct sockaddr_in6 host;

            memset(&host,0,sizeof(struct sockaddr_in6));
            host.sin6_family = AF_INET6;
            memcpy(host.sin6_addr.s6_addr, address->v6.addr, 16);
            host.sin6_port = htons(port);
            //NABTO_LOG_TRACE(LOG, "Connecting to ", PRIep, MAKE_EP_PRINTABLE(*ep));

            status = connect(sock->fd, (struct sockaddr*)&host, sizeof(struct sockaddr_in6));
        }
        if (status == 0) {
            // TODO defer event that socket is connected
        } else if (status == EINPROGRESS) {
            // TODO save async callback
            return NABTO_EC_OK;
        } else {
            NABTO_LOG_ERROR(LOG, "TODO");
            return NABTO_EC_FAILED;
        }
    }
}

void nm_tcp_epoll_is_connected(np_tcp_socket* sock) {
    int err;
    socklen_t len;
    len = sizeof(err);
    if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
        // TODO print error.
    } else {
        if (err == 0) {
            // TODO invoke connect callback

        } else if ( err == EINPROGRESS) {
            // TODO do nothing

        } else {
            // TODO invoke connect callback with error.
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

np_error_code nm_tcp_epoll_async_write(np_tcp_socket* sock, const void* data, size_t dataLength, np_tcp_write_callback cb, void* userData)
{
    if (sock->write.callback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    sock->write.data = data;
    sock->write.dataLength = dataLength;
    sock->write.callback = cb;
    sock->write.userData = userData;

    np_event_queue_post(sock->pl, &sock->write.event, &nm_epoll_tcp_do_write, sock);

    return NABTO_EC_OK;
}

void nm_epoll_tcp_do_read(np_tcp_socket* sock)
{
    if (sock->read.callback == NULL) {
        return;
    }
    int readen = recv(sock->fd, sock->read.buffer, sock->read.bufferSize, 0);
    if (readen < 0) {
        if (readen == EAGAIN || readen == EWOULDBLOCK) {
            // wait for next event.
            return;
        } else {
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
        cb(NABTO_EC_EOF, readen, sock->read.userData);
        return;
    }
}

np_error_code nm_tcp_epoll_async_read(np_tcp_socket* sock, const void* buffer, size_t bufferSize, np_tcp_read_callback cb, void* userData)
{
    if (sock->read.callback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    sock->read.buffer = buffer;
    sock->read.bufferSize = bufferSize;
    sock->read.callback = cb;
    sock->read.userData = userData;
    np_event_queue_post(sock->pl, &sock->read.event, &nm_epoll_tcp_do_read, sock);
    return NABTO_EC_OK;
}

np_error_code nm_tcp_epoll_shutdown(np_tcp_socket* sock)
{
    shutdown(sock->fd, SHUT_WR);
}

np_error_code nm_tcp_epoll_close(np_tcp_socket* sock)
{
    close(sock->fd);
}
