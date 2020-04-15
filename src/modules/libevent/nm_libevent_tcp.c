#include "nm_libevent_tcp.h"
#include "nm_libevent.h"

#include <platform/np_logging.h>
#include <platform/np_platform.h>
#include <platform/np_error_code.h>
#include <platform/np_tcp.h>
#include <platform/np_event_queue.h>

#include <event2/bufferevent.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>


struct tcp_write_context {
    np_tcp_write_callback callback;
    void* userData;
    struct np_event event;
};

struct tcp_connect_context {
    np_tcp_connect_callback callback;
    void* userData;
    struct np_event event;
};

struct tcp_read_context {
    np_tcp_read_callback callback;
    void* userData;
    void* buffer;
    size_t bufferLength;
    struct np_event event;
};

struct np_tcp_socket {
    struct np_platform* pl;
    struct bufferevent* bev;
    struct tcp_write_context write;
    struct tcp_read_context read;
    struct tcp_connect_context connect;
    bool aborted;
    struct np_event abortEv;
};


static np_error_code tcp_create(struct np_platform* pl, np_tcp_socket** sock);
static void tcp_destroy(np_tcp_socket* sock);
static np_error_code tcp_async_connect(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, np_tcp_connect_callback cb, void* userData);
static np_error_code tcp_async_write(np_tcp_socket* sock, const void* data, size_t dataLength, np_tcp_write_callback cb, void* userData);
static np_error_code tcp_async_read(np_tcp_socket* sock, void* buffer, size_t bufferLength, np_tcp_read_callback cb, void* userData);
static np_error_code tcp_shutdown(np_tcp_socket* sock);
static np_error_code tcp_abort(np_tcp_socket* sock);


void nm_libevent_tcp_init(struct np_platform* pl, struct nm_libevent_context* ctx)
{
    pl->tcp.create        = &tcp_create;
    pl->tcp.destroy       = &tcp_destroy;
    pl->tcp.async_connect = &tcp_async_connect;
    pl->tcp.async_write   = &tcp_async_write;
    pl->tcp.async_read    = &tcp_async_read;
    pl->tcp.shutdown      = &tcp_shutdown;
    pl->tcp.abort         = &tcp_abort;
    pl->tcpData = ctx;
}


np_error_code tcp_create(struct np_platform* pl, np_tcp_socket** sock)
{
    struct np_tcp_socket* s = calloc(1, sizeof(struct np_tcp_socket));
    if (s == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    struct nm_libevent_context* ctx = pl->tcpData;

    s->aborted = false;
    s->pl = pl;
    s->bev = bufferevent_socket_new(ctx->eventBase, -1, BEV_OPT_CLOSE_ON_FREE);
    *sock = s;
    return NABTO_EC_OK;
}

static void tcp_connected(void* userData);
static void tcp_written_data(void* userData);
static void tcp_read_data(void* userData);

void tcp_bufferevent_event(struct bufferevent* bev, short event, void* userData)
{
    struct np_tcp_socket* sock = userData;
    if (event & BEV_EVENT_CONNECTED) {
        if (sock->connect.callback) {
            np_event_queue_post(sock->pl, &sock->connect.event, &tcp_connected, userData);
        }
    }
}


void tcp_bufferevent_event_read(struct bufferevent* bev, void* userData)
{
    struct np_tcp_socket* sock = userData;
    np_event_queue_post(sock->pl, &sock->read.event, &tcp_read_data, userData);
}

void tcp_bufferevent_event_write(struct bufferevent* bev, void* userData)
{
    struct np_tcp_socket* sock = userData;
    np_event_queue_post(sock->pl, &sock->write.event, &tcp_written_data, userData);
}

void tcp_connected(void* userData)
{
    struct np_tcp_socket* sock = userData;
    if (sock->connect.callback) {
        np_tcp_connect_callback cb = sock->connect.callback;
        sock->connect.callback = NULL;
        cb(NABTO_EC_OK, sock->connect.userData);
    }
}

void tcp_written_data(void* userData)
{
    struct np_tcp_socket* sock = userData;
    struct evbuffer *output = bufferevent_get_output(sock->bev);
    if (evbuffer_get_length(output) == 0) {
        if (sock->write.callback) {
            np_tcp_write_callback cb = sock->write.callback;
            sock->write.callback = NULL;
            cb(NABTO_EC_OK, sock->write.userData);
        }
    }
}

void tcp_read_data(void* userData)
{
    struct np_tcp_socket* sock = userData;
    if (sock->read.callback) {
        size_t readDataSize = bufferevent_read(sock->bev, sock->read.buffer, sock->read.bufferLength);
        if (readDataSize > 0) {
            np_tcp_read_callback cb = sock->read.callback;
            sock->read.callback = NULL;
            bufferevent_disable(sock->bev, EV_READ);
            cb(NABTO_EC_OK, readDataSize, sock->read.userData);
        }
    }
}

void tcp_destroy(np_tcp_socket* sock)
{
    // TOOD
}

np_error_code tcp_async_connect(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, np_tcp_connect_callback cb, void* userData)
{
    bufferevent_setcb(sock->bev, &tcp_bufferevent_event_read, &tcp_bufferevent_event_write, &tcp_bufferevent_event, sock);
    sock->connect.callback = cb;
    sock->connect.userData = userData;

    bufferevent_enable(sock->bev, EV_WRITE);

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


    return NABTO_EC_OK;


}

np_error_code tcp_async_write(np_tcp_socket* sock, const void* data, size_t dataLength, np_tcp_write_callback cb, void* userData)
{
    if (sock->write.callback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    sock->write.callback = cb;
    sock->write.userData = userData;

    int status = bufferevent_write(sock->bev, data, dataLength);
    if (status == 0) {
        return NABTO_EC_OK;
    } else {
        sock->write.callback = NULL;
        return NABTO_EC_UNKNOWN;
    }
}

np_error_code tcp_async_read(np_tcp_socket* sock, void* buffer, size_t bufferLength, np_tcp_read_callback cb, void* userData)
{
    if (sock->read.callback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    sock->read.callback = cb;
    sock->read.userData = userData;
    sock->read.buffer = buffer;
    sock->read.bufferLength = bufferLength;

    bufferevent_enable(sock->bev, EV_READ);

    return NABTO_EC_OK;
}

np_error_code tcp_shutdown(np_tcp_socket* sock)
{
    evutil_socket_t s = bufferevent_getfd(sock->bev);
    shutdown(s, SHUT_WR);
    return NABTO_EC_OK;
}

np_error_code tcp_abort(np_tcp_socket* sock)
{
    // TODO
    return NABTO_EC_NOT_SUPPORTED;
}
