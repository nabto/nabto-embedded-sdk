#include "nm_libevent.h"

#include <platform/np_logging.h>
#include <platform/np_platform.h>
#include <platform/np_error_code.h>
#include <platform/interfaces/np_tcp.h>
#include <platform/np_completion_event.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>


#if defined(HAVE_WINSOCK2_H)
#include <winsock2.h>
#include <ws2ipdef.h>
#endif


struct tcp_write_context {
    struct np_completion_event* completionEvent;
};

struct tcp_connect_context {
    struct np_completion_event* completionEvent;
};

struct tcp_read_context {
    struct np_completion_event* completionEvent;
    void* buffer;
    size_t bufferLength;
    size_t* readLength;
};

struct np_tcp_socket {
    struct np_platform* pl;
    struct bufferevent* bev;
    struct tcp_write_context write;
    struct tcp_read_context read;
    struct tcp_connect_context connect;
    bool aborted;
};

#define LOG NABTO_LOG_MODULE_TCP

static np_error_code tcp_create(struct np_tcp* obj, struct np_tcp_socket** sock);
static void tcp_destroy(struct np_tcp_socket* sock);
static void tcp_async_connect(struct np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, struct np_completion_event* completionEvent);
static void tcp_async_write(struct np_tcp_socket* sock, const void* data, size_t dataLength, struct np_completion_event* completionEvent);
static void tcp_async_read(struct np_tcp_socket* sock, void* buffer, size_t bufferLength, size_t* readLength, struct np_completion_event* completionEvent);
static void tcp_shutdown(struct np_tcp_socket* sock);

static void tcp_abort(struct np_tcp_socket* sock);
static void tcp_bufferevent_event_read(struct bufferevent* bev, void* userData);
static void tcp_bufferevent_event_write(struct bufferevent* bev, void* userData);
static void resolve_tcp_connect(struct np_tcp_socket* sock, np_error_code ec);
static void resolve_tcp_read(struct np_tcp_socket* sock, np_error_code ec);
static void resolve_tcp_write(struct np_tcp_socket* sock, np_error_code ec);
static void tcp_eof(void* userData);

static struct np_tcp_functions module = {
    .create = tcp_create,
    .destroy = tcp_destroy,
    .async_connect = tcp_async_connect,
    .async_write = tcp_async_write,
    .async_read = tcp_async_read,
    .shutdown = tcp_shutdown,
    .abort = tcp_abort
};

struct np_tcp nm_libevent_tcp_get_impl(struct nm_libevent_context* ctx)
{
    struct np_tcp obj;
    obj.mptr = &module;
    obj.data = ctx;
    return obj;
}

np_error_code tcp_create(struct np_tcp* obj, struct np_tcp_socket** sock)
{
    NABTO_LOG_TRACE(LOG, "tcp_create");
    struct np_tcp_socket* s = calloc(1, sizeof(struct np_tcp_socket));
    if (s == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    struct nm_libevent_context* ctx = obj->data;

    s->aborted = false;
    s->bev = bufferevent_socket_new(ctx->eventBase, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);

#ifdef SO_NOSIGPIPE
    evutil_socket_t fd = bufferevent_getfd(s->bev);
    if (fd > 0) {
        int value = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof(value));
    }
#endif

    *sock = s;

    return NABTO_EC_OK;
}

static void tcp_eof(void* userData);

void tcp_bufferevent_event(struct bufferevent* bev, short event, void* userData)
{
    struct np_tcp_socket* sock = userData;
    NABTO_LOG_TRACE(LOG, "bufferevent event %i", event);
    if (event & BEV_EVENT_CONNECTED) {
        resolve_tcp_connect(sock, NABTO_EC_OK);
    } else if (event & BEV_EVENT_EOF || event & BEV_EVENT_ERROR) {
        tcp_eof(sock);
    }
}

void tcp_bufferevent_event_read(struct bufferevent* bev, void* userData)
{
    NABTO_LOG_TRACE(LOG, "tcp_bufferevent_event_read");
    struct np_tcp_socket* sock = userData;
    if (sock->read.completionEvent != NULL) {
        size_t readDataSize = bufferevent_read(sock->bev, sock->read.buffer, sock->read.bufferLength);
        if (readDataSize > 0) {
            *(sock->read.readLength) = readDataSize;
            struct np_completion_event* e = sock->read.completionEvent;
            sock->read.completionEvent = NULL;
            bufferevent_disable(sock->bev, EV_READ);
            np_completion_event_resolve(e, NABTO_EC_OK);
        }
    }
}

void tcp_bufferevent_event_write(struct bufferevent* bev, void* userData)
{
    struct np_tcp_socket* sock = userData;
    NABTO_LOG_TRACE(LOG, "tcp_written_data");

    if (sock->connect.completionEvent != NULL) {
        resolve_tcp_connect(sock, NABTO_EC_OK);
    }

    struct evbuffer *output = bufferevent_get_output(sock->bev);
    if (evbuffer_get_length(output) == 0) {
        resolve_tcp_write(sock, NABTO_EC_OK);
    }
}

void resolve_tcp_connect(struct np_tcp_socket* sock, np_error_code ec)
{
    if (sock->connect.completionEvent != NULL) {
        struct np_completion_event* e = sock->connect.completionEvent;
        sock->connect.completionEvent = NULL;
        np_completion_event_resolve(e, ec);
    }
}

void resolve_tcp_write(struct np_tcp_socket* sock, np_error_code ec)
{
    if (sock->write.completionEvent != NULL) {
        struct np_completion_event* e = sock->write.completionEvent;
        sock->write.completionEvent = NULL;
        np_completion_event_resolve(e, ec);
    }
}

void resolve_tcp_read(struct np_tcp_socket* sock, np_error_code ec)
{
    NABTO_LOG_TRACE(LOG, "resolve_tcp_read");
    if (sock->read.completionEvent != NULL) {
        struct np_completion_event* e = sock->read.completionEvent;
        sock->read.completionEvent = NULL;
        np_completion_event_resolve(e, ec);
    }
}

void tcp_eof(void* userData)
{
    struct np_tcp_socket* sock = userData;
    NABTO_LOG_TRACE(LOG, "tcp_eof");
    resolve_tcp_connect(sock, NABTO_EC_EOF);
    resolve_tcp_read(sock, NABTO_EC_EOF);
}

void tcp_destroy(struct np_tcp_socket* sock)
{
    bufferevent_disable(sock->bev, EV_READ);
    tcp_abort(sock);

    bufferevent_free(sock->bev);
    free(sock);
}

void tcp_async_connect(struct np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, struct np_completion_event* completionEvent)
{
    NABTO_LOG_TRACE(LOG, "tcp_async_connect");

    bufferevent_setcb(sock->bev, &tcp_bufferevent_event_read, &tcp_bufferevent_event_write, &tcp_bufferevent_event, sock);
    sock->connect.completionEvent = completionEvent;

    bufferevent_enable(sock->bev, EV_READ|EV_WRITE);

    if (address->type == NABTO_IPV6) {
        struct sockaddr_in6 in;
        in.sin6_family = AF_INET6;
        in.sin6_flowinfo = 0;
        in.sin6_scope_id = 0;
        in.sin6_port = htons(port);
        memcpy((void*)&in.sin6_addr,address->ip.v6, sizeof(in.sin6_addr));
        bufferevent_socket_connect(sock->bev, (struct sockaddr*)&in, sizeof(struct sockaddr_in6));
    } else { // IPV4
        struct sockaddr_in in;
        in.sin_family = AF_INET;
        in.sin_port = htons(port);
        memcpy((void*)&in.sin_addr, address->ip.v4, sizeof(in.sin_addr));
        bufferevent_socket_connect(sock->bev, (struct sockaddr*)&in, sizeof(struct sockaddr_in));
    }
}

void tcp_async_write(struct np_tcp_socket* sock, const void* data, size_t dataLength, struct np_completion_event* completionEvent)
{
    if (sock->write.completionEvent != NULL) {
        np_completion_event_resolve(completionEvent, NABTO_EC_OPERATION_IN_PROGRESS);
        return;
    }
    sock->write.completionEvent = completionEvent;
    bufferevent_enable(sock->bev, EV_WRITE);
    int status = bufferevent_write(sock->bev, data, dataLength);
    if (status == 0) {
        return;
    } else {
        sock->write.completionEvent = NULL;
        np_completion_event_resolve(completionEvent, NABTO_EC_UNKNOWN);
        return;
    }
}

void tcp_async_read(struct np_tcp_socket* sock, void* buffer, size_t bufferLength, size_t* readLength, struct np_completion_event* completionEvent)
{
    NABTO_LOG_TRACE(LOG, "tcp_async_read");
    if (sock->read.completionEvent != NULL) {
        np_completion_event_resolve(sock->read.completionEvent, NABTO_EC_OPERATION_IN_PROGRESS);
        return;
    }

    sock->read.completionEvent = completionEvent;
    sock->read.buffer = buffer;
    sock->read.bufferLength = bufferLength;
    sock->read.readLength = readLength;

    size_t readDataSize = bufferevent_read(sock->bev, sock->read.buffer, sock->read.bufferLength);
    if (readDataSize > 0) {
        *(sock->read.readLength) = readDataSize;
        struct np_completion_event* e = sock->read.completionEvent;
        sock->read.completionEvent = NULL;
        bufferevent_disable(sock->bev, EV_READ);
        np_completion_event_resolve(e, NABTO_EC_OK);
    } else {
        bufferevent_enable(sock->bev, EV_READ);
    }
    return;
}

void tcp_shutdown(struct np_tcp_socket* sock)
{
    evutil_socket_t s = bufferevent_getfd(sock->bev);
#if defined(HAVE_WINSOCK2_H)
    shutdown(s, SD_SEND);
#else
    shutdown(s, SHUT_WR);
#endif
}

void tcp_abort(struct np_tcp_socket* sock)
{
    if (sock->aborted == true) {
        return;
    }
    sock->aborted = true;

    resolve_tcp_connect(sock, NABTO_EC_ABORTED);
    resolve_tcp_read(sock, NABTO_EC_ABORTED);
    resolve_tcp_write(sock, NABTO_EC_ABORTED);
}
