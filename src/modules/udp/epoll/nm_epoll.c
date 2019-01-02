#include "nm_epoll.h"
#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <platform/np_event_queue.h>
#include <platform/np_communication_buffer.h>

#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>

#define LOG NABTO_LOG_MODULE_UDP

struct nm_epoll_created_ctx {
    np_udp_socket_created_callback cb;
    void* data;
    struct np_event event;
    uint16_t port;
};

struct nm_epoll_destroyed_ctx {
    np_udp_socket_destroyed_callback cb;
    void* data;
    struct np_event event;
};

struct nm_epoll_received_ctx {
    np_udp_packet_received_callback cb;
    void* data;
    struct np_event event;
};

struct np_udp_socket {
    int sock;
    bool isIpv6;
    struct nm_epoll_created_ctx created;
    struct nm_epoll_destroyed_ctx des;
    struct nm_epoll_received_ctx recv;
    bool sending;
};

static int nm_epoll_fd = -1;
static struct np_platform* pl = 0;
static np_communication_buffer* recv_buf;
struct epoll_event events[64];

/**
 * Handles events from epoll_wait
 */
void nm_epoll_handle_event(np_udp_socket* sock); // consider an np_epoll_event type instead of reusing the socket structure

/**
 * async functions implementing epoll functionallity for the udp
 * interface of <platform/udp.h> used in the np_platform.
 */
void nm_epoll_async_create(np_udp_socket_created_callback cb, void* data);
void nm_epoll_async_bind_port(uint16_t port, np_udp_socket_created_callback cb, void* data);
void nm_epoll_async_send_to(struct np_udp_send_context* ctx);
void nm_epoll_async_recv_from(np_udp_socket* socket,
                              np_udp_packet_received_callback cb, void* data);
enum np_ip_address_type nm_epoll_get_protocol(np_udp_socket* socket);
uint16_t nm_epoll_get_local_port(np_udp_socket* socket);
void nm_epoll_async_destroy(np_udp_socket* socket, np_udp_socket_destroyed_callback cb, void* data);

void nm_epoll_cancel_all_events(np_udp_socket* sock)
{
    NABTO_LOG_TRACE(LOG, "Cancelling all events");
    np_event_queue_cancel_event(pl, &sock->created.event);
    np_event_queue_cancel_event(pl, &sock->des.event);
    np_event_queue_cancel_event(pl, &sock->recv.event);
}

void nm_epoll_free_socket(np_udp_socket* sock)
{
    NABTO_LOG_TRACE(LOG, "shutdown with data: %u", sock->des.data);
    if (epoll_ctl(nm_epoll_fd, EPOLL_CTL_DEL, sock->sock, NULL) == -1) {
        NABTO_LOG_ERROR(LOG,"Cannot remove fd from epoll set, %i: %s", errno, strerror(errno));
    }
    {
        np_udp_socket_destroyed_callback cb;
        void* cbData;
        close(sock->sock);
        nm_epoll_cancel_all_events(sock);
        cb = sock->des.cb;
        cbData = sock->des.data;
        free(sock);
        if (cb) {
            cb(NABTO_EC_OK, cbData);
        }
    }
}

void nm_epoll_cancel_recv_from(np_udp_socket* socket)
{
    np_event_queue_cancel_event(pl, &socket->recv.event);
    socket->recv.cb = NULL;
}

void nm_epoll_cancel_send_to(struct np_udp_send_context* ctx)
{
    np_event_queue_cancel_event(pl, &ctx->ev);
    ctx->cb = NULL;
}

void nm_epoll_init(struct np_platform* pl_in) {
    if(!pl_in) {
        NABTO_LOG_FATAL(LOG, "No np_platform provided");
        return;
    }
    pl = pl_in;
    pl->udp.async_create    = &nm_epoll_async_create;
    pl->udp.async_bind_port = &nm_epoll_async_bind_port;
    pl->udp.async_send_to   = &nm_epoll_async_send_to;
    pl->udp.async_recv_from = &nm_epoll_async_recv_from;
    pl->udp.cancel_recv_from = &nm_epoll_cancel_recv_from;
    pl->udp.cancel_send_to = &nm_epoll_cancel_send_to;
    pl->udp.get_protocol    = &nm_epoll_get_protocol;
    pl->udp.get_local_port  = &nm_epoll_get_local_port;
    pl->udp.async_destroy   = &nm_epoll_async_destroy;
    nm_epoll_fd = epoll_create(42 /*unused*/);
    recv_buf = pl->buf.allocate();
    if (nm_epoll_fd == -1) {
        NABTO_LOG_FATAL(LOG, "Failed to create epoll socket: (%i) '%s'.", errno, strerror(errno));
    }
}

void nm_epoll_close(struct np_platform* pl)
{
    close(nm_epoll_fd);
    pl->buf.free(recv_buf);
}

enum np_ip_address_type nm_epoll_get_protocol(np_udp_socket* socket)
{
    if(socket->isIpv6) {
        return NABTO_IPV6;
    } else {
        return NABTO_IPV4;
    }
}

uint16_t nm_epoll_get_local_port(np_udp_socket* socket)
{
    struct sockaddr_in6 addr;
    socklen_t length = sizeof(struct sockaddr_in6);
    getsockname(socket->sock, (struct sockaddr*)(&addr), &length);
    return htons(addr.sin6_port);
}

void nm_epoll_read(int nfds)
{
//    struct epoll_event events[64];
//    NABTO_LOG_TRACE(LOG, "epoll_wait returned with %i file descriptors", nfds);
    for (int i = 0; i < nfds; i++) {
        if((events[i].events & EPOLLERR) ||
           (events[i].events & EPOLLHUP) ||
           (!(events[i].events & EPOLLIN))) {
            NABTO_LOG_TRACE(LOG, "epoll event with socket error %x", events[i].events);
            {
                np_udp_socket* sock = (np_udp_socket*)events[i].data.ptr;
                NABTO_LOG_TRACE(LOG, "read with data: %u", sock->des.data);
                np_udp_socket_destroyed_callback cb;
                void* cbData;
                cb = sock->des.cb;
                cbData = sock->des.data;
                if (cb != NULL) {
                    cb(NABTO_EC_OK, cbData);
                }
            }
            continue;
        }
        np_udp_socket* sock = (np_udp_socket*)events[i].data.ptr;
        nm_epoll_handle_event(sock);
    }
}

int nm_epoll_wait(uint32_t ms)
{
    int nfds;
    if (ms == 0) {
//        NABTO_LOG_TRACE(LOG, "epoll waits forever");
        nfds = epoll_wait(nm_epoll_fd, events, 64, -1);
    } else {
//        NABTO_LOG_TRACE(LOG, "waits for %u ms", ms);
        nfds = epoll_wait(nm_epoll_fd, events, 64, ms);
    }
    if (nfds < 0) {
        NABTO_LOG_ERROR(LOG, "Error in epoll wait: (%i) '%s'", errno, strerror(errno));
    }
//    NABTO_LOG_TRACE(LOG, "epoll_wait returned with %i file descriptors", nfds);
    return nfds;
}

void nm_epoll_handle_event(np_udp_socket* sock) {
    NABTO_LOG_TRACE(LOG, "handle event");
    struct np_udp_endpoint ep;
    ssize_t recvLength;
    uint8_t* start;
    start = pl->buf.start(recv_buf);
    if (sock->isIpv6) {
        struct sockaddr_in6 sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, start,  pl->buf.size(recv_buf), 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.v6.addr,&sa.sin6_addr.s6_addr, sizeof(ep.ip.v6.addr));
        ep.port = ntohs(sa.sin6_port);
        ep.ip.type = NABTO_IPV6;
    } else {
        struct sockaddr_in sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, start, pl->buf.size(recv_buf), 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.v4.addr,&sa.sin_addr.s_addr, sizeof(ep.ip.v4.addr));
        ep.port = ntohs(sa.sin_port);
        ep.ip.type = NABTO_IPV4;
    }
    if (recvLength < 0) {
        int status = errno;
        if (status == EAGAIN || EWOULDBLOCK) {
            // expected
            return;
        } else {
            np_udp_packet_received_callback cb;
            NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_epoll_handle_event", strerror(status), (int) status);
            if(sock->recv.cb) {
                cb = sock->recv.cb;
                sock->recv.cb = NULL;
                cb(NABTO_EC_UDP_SOCKET_ERROR, ep, NULL, 0, sock->recv.data);
            }
            nm_epoll_free_socket(sock);
            return;
        }
    }
    if (sock->recv.cb) {
        np_udp_packet_received_callback cb = sock->recv.cb;
        sock->recv.cb = NULL;
        NABTO_LOG_TRACE(LOG, "received data, invoking callback");
        cb(NABTO_EC_OK, ep, recv_buf, recvLength, sock->recv.data);
    }
    nm_epoll_handle_event(sock);
}

void nm_epoll_event_create(void* data)
{
    np_udp_socket* us = (np_udp_socket*)data;
    struct epoll_event* ev;

    us->sock = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (us->sock == -1) {
        us->sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (us->sock == -1) {
            np_error_code ec;
            NABTO_LOG_ERROR(LOG, "Unable to create socket: (%i) '%s'.", errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR;
            us->created.cb(ec, NULL, us->created.data);
            nm_epoll_cancel_all_events(us);
            free(us);
            return;
        } else {
            NABTO_LOG_WARN(LOG, "IPv4 socket opened since IPv6 socket creation failed");
            us->isIpv6 = false;
        }
    } else {
        int no = 0;
        us->isIpv6 = true;
        if (setsockopt(us->sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no)))
        {
            np_error_code ec;
            NABTO_LOG_ERROR(LOG,"Unable to set option: (%i) '%s'.", errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR; 
            close(us->sock);
            us->created.cb(ec, NULL, us->created.data);
            nm_epoll_cancel_all_events(us);
            free(us);
            return;
        }        
    }
    ev = (struct epoll_event*)malloc(sizeof(struct epoll_event));
    ev->events = EPOLLIN | EPOLLET;
    ev->data.ptr = us;
    if (epoll_ctl(nm_epoll_fd, EPOLL_CTL_ADD, us->sock, ev) == -1) {
        NABTO_LOG_FATAL(LOG,"could not add file descriptor to epoll set: (%i) '%s'", errno, strerror(errno));
        close(us->sock);
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, NULL, us->created.data);
        nm_epoll_cancel_all_events(us);
        free(us);
        return;
    }
    us->created.cb(NABTO_EC_OK, us, us->created.data);
    return;
}

void nm_epoll_async_create(np_udp_socket_created_callback cb, void* data)
{
    np_udp_socket* sock;

    sock = (np_udp_socket*)malloc(sizeof(np_udp_socket));
    sock->created.cb = cb;
    sock->created.data = data;
    sock->sending = false;
    np_event_queue_post(pl, &sock->created.event, &nm_epoll_event_create, sock);
}


void nm_epoll_event_destroy(void* data)
{
    np_udp_socket* sock = (np_udp_socket*)data;
    if (sock == NULL) {
        return;
    }
    shutdown(sock->sock, SHUT_RDWR);
    NABTO_LOG_TRACE(LOG, "shutdown with data: %u", sock->des.data);
    return;
    
/*    if (epoll_ctl(nm_epoll_fd, EPOLL_CTL_DEL, sock->sock, NULL) == -1) {
        NABTO_LOG_ERROR(LOG,"Cannot remove fd from epoll set, %i: %s", errno, strerror(errno));
    }
    close(sock->sock);
    cb = sock->des.cb;
    cbData = sock->des.data;
    nm_epoll_cancel_all_events(sock);
    free(sock);
    cb(NABTO_EC_OK, cbData);
*/
}

void nm_epoll_async_destroy(np_udp_socket* socket, np_udp_socket_destroyed_callback cb, void* data)
{
    NABTO_LOG_TRACE(LOG, "Destroying with data: %u", data);
    socket->des.cb = cb;
    socket->des.data = data;
    NABTO_LOG_TRACE(LOG, "Destroying with data: %u", socket->des.data);
    np_event_queue_post(pl, &socket->des.event, nm_epoll_event_destroy, socket);

}

void nm_epoll_event_bind_port(void* data) {
    np_udp_socket* us = (np_udp_socket*)data;
    struct epoll_event* ev;

    us->sock = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (us->sock == -1) {
        us->sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (us->sock == -1) {
            np_error_code ec;
            NABTO_LOG_ERROR(LOG, "Unable to create socket: (%i) '%s'.", errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR;
            us->created.cb(ec, NULL, us->created.data);
            nm_epoll_cancel_all_events(us);
            free(us);
            return;
        } else {
            NABTO_LOG_WARN(LOG, "IPv4 socket opened since IPv6 socket creation failed");
            us->isIpv6 = false;
        }
    } else {
        int no = 0;
        us->isIpv6 = true;
        if (setsockopt(us->sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no)))
        {
            np_error_code ec;
            NABTO_LOG_ERROR(LOG,"Unable to set option: (%i) '%s'.", errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR; 
            close(us->sock);
            us->created.cb(ec, NULL, us->created.data);
            nm_epoll_cancel_all_events(us);
            free(us);
            return;
        }        
    }
    int i;
    if(us->isIpv6) {
        struct sockaddr_in6 si_me6;
        si_me6.sin6_family = AF_INET6;
        si_me6.sin6_port = htons(us->created.port);
        si_me6.sin6_addr = in6addr_any;
        i = bind(us->sock, (struct sockaddr*)&si_me6, sizeof(si_me6));
        NABTO_LOG_INFO(LOG, "bind returned %i", i);
    } else {
        struct sockaddr_in si_me;
        si_me.sin_family = AF_INET;
        si_me.sin_port = htons(us->created.port);
        si_me.sin_addr.s_addr = INADDR_ANY;
        i = bind(us->sock, (struct sockaddr*)&si_me, sizeof(si_me));
        NABTO_LOG_INFO(LOG, "bind returned %i", i);
    }
    if (i != 0) {
        np_error_code ec;
        NABTO_LOG_ERROR(LOG,"Unable to bind to port %i: (%i) '%s'.", us->created.port, errno, strerror(errno));
        ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        close(us->sock);
        us->created.cb(ec, NULL, us->created.data);
        nm_epoll_cancel_all_events(us);
        free(us);
        return;
    }
    ev = (struct epoll_event*)malloc(sizeof(struct epoll_event));
    ev->events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev->data.ptr = us;
    if (epoll_ctl(nm_epoll_fd, EPOLL_CTL_ADD, us->sock, ev) == -1) {
        NABTO_LOG_FATAL(LOG,"could not add file descriptor to epoll set: (%i) '%s'", errno, strerror(errno));
        close(us->sock);
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, NULL, us->created.data);
        nm_epoll_cancel_all_events(us);
        free(us);
        return;
    }
    us->created.cb(NABTO_EC_OK, us, us->created.data);
    return;
    
}
void nm_epoll_async_bind_port(uint16_t port, np_udp_socket_created_callback cb, void* data)
{
    np_udp_socket* sock;
    sock = (np_udp_socket*)malloc(sizeof(np_udp_socket));
    sock->created.cb = cb;
    sock->created.data = data;
    sock->created.port = port;
    np_event_queue_post(pl, &sock->created.event, nm_epoll_event_bind_port, sock);
}

void nm_epoll_event_send_to(void* data){
    struct np_udp_send_context* ctx = (struct np_udp_send_context*)data;
    np_udp_socket* sock = ctx->sock;
    ssize_t res;
    if (ctx->ep.ip.type == NABTO_IPV4) {
        struct sockaddr_in srv_addr;
        srv_addr.sin_family = AF_INET;
        srv_addr.sin_port = htons (ctx->ep.port);
        memcpy((void*)&srv_addr.sin_addr, ctx->ep.ip.v4.addr, sizeof(srv_addr.sin_addr));
        NABTO_LOG_TRACE(LOG, "Sending to v4: %u.%u.%u.%u:%u", ctx->ep.ip.v4.addr[0], ctx->ep.ip.v4.addr[1], ctx->ep.ip.v4.addr[2], ctx->ep.ip.v4.addr[3], ctx->ep.port);
        res = sendto (sock->sock, pl->buf.start(ctx->buffer), ctx->bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    } else { // IPv6
        struct sockaddr_in6 srv_addr;
        srv_addr.sin6_family = AF_INET6;
        srv_addr.sin6_flowinfo = 0;
        srv_addr.sin6_scope_id = 0;
        srv_addr.sin6_port = htons (ctx->ep.port);
        memcpy((void*)&srv_addr.sin6_addr,ctx->ep.ip.v6.addr, sizeof(srv_addr.sin6_addr));
        res = sendto (sock->sock, pl->buf.start(ctx->buffer), ctx->bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    }
    if (res < 0) {
        int status = errno;
        NABTO_LOG_TRACE(LOG, "UDP returned error status %i", status);
        if (status == EAGAIN || status == EWOULDBLOCK) {
            // expected
        } else {
            NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_epoll_event_send_to", (int) status, strerror(status));
            if (ctx->cb) {
                ctx->cb(NABTO_EC_FAILED_TO_SEND_PACKET, ctx->cbData);
            }
            sock->sending = false;
            return;
        }
    }
    if (ctx->cb) {
        ctx->cb(NABTO_EC_OK, ctx->cbData);
    }
    sock->sending = false;
    return;
}

void nm_epoll_retry_send_to(void* data)
{
    struct np_udp_send_context* ctx = (struct np_udp_send_context*)data;
    if (ctx->sock->sending) {
        NABTO_LOG_TRACE(LOG, "Already sending, reretrying " PRIip4 " in a bit", MAKE_IPV4_PRINTABLE(ctx->ep.ip.v4.addr));
        np_event_queue_post(pl, &ctx->ev, nm_epoll_retry_send_to, ctx);
    } else {
        NABTO_LOG_TRACE(LOG, "No longer sending, sending now");
        ctx->sock->sending = true;
        np_event_queue_post(pl, &ctx->ev, nm_epoll_event_send_to, ctx);
    }
}

void nm_epoll_async_send_to(struct np_udp_send_context* ctx)
//    np_udp_socket* socket, struct np_udp_endpoint* ep, np_communication_buffer* buffer, uint16_t bufferSize, np_udp_packet_sent_callback cb, void* data)
{
    /* socket->sent.ep = ep; */
    /* socket->sent.buf = buffer; */
    /* socket->sent.bufSize = bufferSize; */
    /* socket->sent.cb = cb; */
    /* socket->sent.data = data; */
    if (ctx->sock->sending) {
        NABTO_LOG_TRACE(LOG, "Already sending, retrying in a bit");
        np_event_queue_post(pl, &ctx->ev, nm_epoll_retry_send_to, ctx);
    } else {
        ctx->sock->sending = true;
        np_event_queue_post(pl, &ctx->ev, nm_epoll_event_send_to, ctx);
    }
}

void nm_epoll_async_recv_from(np_udp_socket* socket,
                              np_udp_packet_received_callback cb, void* data)
{
    socket->recv.cb = cb;
    socket->recv.data = data;
}


