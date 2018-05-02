#include "nm_epoll.h"
#include <platform/platform.h>
#include <platform/logging.h>
#include <platform/event_queue.h>
#include <platform/communication_buffer.h>

#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>

struct nm_epoll_created_ctx {
    nabto_udp_socket_created_callback cb;
    void* data;
    struct nabto_event* event;
    uint16_t port;
};

struct nm_epoll_destroyed_ctx {
    nabto_udp_socket_destroyed_callback cb;
    void* data;
    struct nabto_event* event;
};

struct nm_epoll_sent_ctx {
    nabto_udp_packet_sent_callback cb;
    void* data;
    struct nabto_event* event;
    struct nabto_udp_endpoint* ep;
    uint8_t* buf;
    uint16_t bufSize;
};

struct nm_epoll_received_ctx {
    nabto_udp_packet_received_callback cb;
    void* data;
    struct nabto_event* event;
};

struct nabto_udp_socket {
    int sock;
    bool isIpv6;
    struct nm_epoll_created_ctx created;
    struct nm_epoll_destroyed_ctx des;
    struct nm_epoll_sent_ctx sent;
    struct nm_epoll_received_ctx recv;
};

static int nm_epoll_fd = -1;
static struct nabto_platform* pl = 0;
static nabto_communication_buffer* recv_buf;

void nm_epoll_init(struct nabto_platform* pl_in) {
    if(!pl_in) {
        NABTO_LOG_FATAL(NABTO_LOG_MODULE_UDP, "No nabto_platform provided");
        return;
    }
    pl = pl_in;
    pl->udp.async_create    = &nm_epoll_async_create;
    pl->udp.async_bind_port = &nm_epoll_async_bind_port;
    pl->udp.async_send_to   = &nm_epoll_async_send_to;
    pl->udp.async_recv_from = &nm_epoll_async_recv_from;
    pl->udp.async_destroy   = &nm_epoll_async_destroy;
    nm_epoll_fd = epoll_create(42 /*unused*/);
    recv_buf = pl->buf.allocate();
    if (nm_epoll_fd == -1) {
        NABTO_LOG_FATAL(NABTO_LOG_MODULE_UDP, "Failed to create epoll socket: (%i) '%s'.", errno, strerror(errno));
    }
}

void nm_epoll_wait()
{
    struct epoll_event events[64];
    int nfds;
    if (nabto_event_queue_has_timed_event(pl)) {
        uint32_t ms = nabto_event_queue_next_timed_event_occurance(pl);
        NABTO_LOG_TRACE(NABTO_LOG_MODULE_UDP, "Found timed events, epoll waits for %u ms", ms);
        nfds = epoll_wait(nm_epoll_fd, events, 64, ms);
    } else {
        NABTO_LOG_TRACE(NABTO_LOG_MODULE_UDP, "no timed events, epoll waits forever");
        nfds = epoll_wait(nm_epoll_fd, events, 64, -1);
    }
    if (nfds < 0) {
        NABTO_LOG_FATAL(NABTO_LOG_MODULE_UDP, "Error in epoll wait: (%i) '%s'", errno, strerror(errno));
        exit(1);
    }
    NABTO_LOG_TRACE(NABTO_LOG_MODULE_UDP, "epoll_wait returned with %i file descriptors", nfds);
    for (int i = 0; i < nfds; i++) {
        if((events[i].events & EPOLLERR) ||
           (events[i].events & EPOLLHUP) ||
           (!(events[i].events & EPOLLIN))) {
            NABTO_LOG_TRACE(NABTO_LOG_MODULE_UDP, "epoll event with socket error");
            continue;
        }
        nabto_udp_socket* sock = (nabto_udp_socket*)events[i].data.ptr;
        nm_epoll_handle_event(sock);
    }

}
void nm_epoll_handle_event(nabto_udp_socket* sock) {
    struct nabto_udp_endpoint ep;
    uint16_t recvLength;
    if (sock->isIpv6) {
        struct sockaddr_in6 sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, pl->buf.start(recv_buf),  pl->buf.size(recv_buf), 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.v6.addr,&sa.sin6_addr.s6_addr, sizeof(ep.ip.v6.addr));
        ep.port = ntohs(sa.sin6_port);
    } else {
        struct sockaddr_in sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, pl->buf.start(recv_buf),  pl->buf.size(recv_buf), 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.v4.addr,&sa.sin_addr.s_addr, sizeof(ep.ip.v4.addr));
        ep.port = ntohs(sa.sin_port);
    }
    sock->recv.cb(NABTO_EC_OK, ep, recv_buf, recvLength, sock->recv.data);
}

void nm_epoll_event_create(void* data)
{
    nabto_udp_socket* us = (nabto_udp_socket*)data;
    struct epoll_event* ev;
    free(us->created.event);
    us->created.event = NULL;

    us->sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (us->sock == -1) {
        us->sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (us->sock == -1) {
            nabto_error_code ec;
            NABTO_LOG_ERROR(NABTO_LOG_MODULE_UDP, "Unable to create socket: (%i) '%s'.", errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR;
            us->created.cb(ec, NULL, us->created.data);
            free(us);
            return;
        } else {
            NABTO_LOG_WARN(NABTO_LOG_MODULE_UDP, "IPv4 socket opened since IPv6 socket creation failed");
            us->isIpv6 = false;
        }
    } else {
        int no = 0;
        us->isIpv6 = true;
        if (setsockopt(us->sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no)))
        {
            nabto_error_code ec;
            NABTO_LOG_ERROR(NABTO_LOG_MODULE_UDP,"Unable to set option: (%i) '%s'.", errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR; 
            close(us->sock);
            us->created.cb(ec, NULL, us->created.data);
            free(us);
            return;
        }        
    }
    ev = (struct epoll_event*)malloc(sizeof(struct epoll_event));
    ev->events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev->data.ptr = us;
    if (epoll_ctl(nm_epoll_fd, EPOLL_CTL_ADD, us->sock, ev) == -1) {
        NABTO_LOG_FATAL(NABTO_LOG_MODULE_UDP,"could not add file descriptor to epoll set: (%i) '%s'", errno, strerror(errno));
        close(us->sock);
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, NULL, us->created.data);
        free(us);
        return;
    }
    us->created.cb(NABTO_EC_OK, us, us->created.data);
    return;
}

void nm_epoll_async_create(nabto_udp_socket_created_callback cb, void* data)
{
    struct nabto_event* ne;
    nabto_udp_socket* sock;

    sock = (nabto_udp_socket*)malloc(sizeof(nabto_udp_socket));
    sock->created.cb = cb;
    sock->created.data = data;
    ne = (struct nabto_event*)malloc(sizeof(struct nabto_event));
    sock->created.event = ne; 
    nabto_event_queue_post(pl, ne, &nm_epoll_event_create, sock);
}


void nm_epoll_event_destroy(void* data)
{
    nabto_udp_socket* sock = (nabto_udp_socket*)data;
    if (epoll_ctl(nm_epoll_fd, EPOLL_CTL_DEL, sock->sock, NULL) == -1) {
        NABTO_LOG_ERROR(NABTO_LOG_MODULE_UDP,"Cannot remove fd from epoll set, %i: %s", errno, strerror(errno));
    }
    close(sock->sock);
    free(sock->des.event);
    if(sock->created.event) {
        free(sock->created.event);
    }
    if(sock->sent.event) {
        free(sock->sent.event);
    }
    if(sock->recv.event) {
        free(sock->recv.event);
    }
    sock->des.cb(NABTO_EC_OK, sock->des.data);
    free(sock);
}

void nm_epoll_async_destroy(nabto_udp_socket* socket, nabto_udp_socket_destroyed_callback cb, void* data)
{
    struct nabto_event* ne;
    ne = (struct nabto_event*)malloc(sizeof(struct nabto_event));
    socket->des.cb = cb;
    socket->des.event = ne;
    socket->des.data = data;
    nabto_event_queue_post(pl, ne, nm_epoll_event_destroy, socket);

}

void nm_epoll_event_bind_port(void* data) {
    nabto_udp_socket* us = (nabto_udp_socket*)data;
    struct epoll_event* ev;
    struct sockaddr_in si_me;
    free(us->created.event);
    us->created.event = NULL;

    us->sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (us->sock == -1) {
        us->sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (us->sock == -1) {
            nabto_error_code ec;
            NABTO_LOG_ERROR(NABTO_LOG_MODULE_UDP, "Unable to create socket: (%i) '%s'.", errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR;
            us->created.cb(ec, NULL, us->created.data);
            free(us);
            return;
        } else {
            NABTO_LOG_WARN(NABTO_LOG_MODULE_UDP, "IPv4 socket opened since IPv6 socket creation failed");
            us->isIpv6 = false;
        }
    } else {
        int no = 0;
        us->isIpv6 = true;
        if (setsockopt(us->sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no)))
        {
            nabto_error_code ec;
            NABTO_LOG_ERROR(NABTO_LOG_MODULE_UDP,"Unable to set option: (%i) '%s'.", errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR; 
            close(us->sock);
            us->created.cb(ec, NULL, us->created.data);
            free(us);
            return;
        }        
    }
    si_me.sin_family = AF_INET6;
    si_me.sin_port = htons(us->created.port);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(us->sock, (struct sockaddr*)&si_me, sizeof(si_me)) == -1) {
        nabto_error_code ec;
        NABTO_LOG_ERROR(NABTO_LOG_MODULE_UDP,"Unable to bind to port %i: (%i) '%s'.", us->created.port, errno, strerror(errno));
        ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        close(us->sock);
        us->created.cb(ec, NULL, us->created.data);
        free(us);
        return;
    }
    ev = (struct epoll_event*)malloc(sizeof(struct epoll_event));
    ev->events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev->data.ptr = us;
    if (epoll_ctl(nm_epoll_fd, EPOLL_CTL_ADD, us->sock, ev) == -1) {
        NABTO_LOG_FATAL(NABTO_LOG_MODULE_UDP,"could not add file descriptor to epoll set: (%i) '%s'", errno, strerror(errno));
        close(us->sock);
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, NULL, us->created.data);
        free(us);
        return;
    }
    us->created.cb(NABTO_EC_OK, us, us->created.data);
    return;
    
}
void nm_epoll_async_bind_port(uint16_t port, nabto_udp_socket_created_callback cb, void* data)
{
    struct nabto_event* ne;
    nabto_udp_socket* sock;
    sock = (nabto_udp_socket*)malloc(sizeof(nabto_udp_socket));
    sock->created.cb = cb;
    sock->created.data = data;
    sock->created.port = port;
    ne = (struct nabto_event*)malloc(sizeof(struct nabto_event));
    sock->created.event = ne;
    nabto_event_queue_post(pl, ne, nm_epoll_event_bind_port, sock);
}

void nm_epoll_event_send_to(void* data){
    nabto_udp_socket* sock = (nabto_udp_socket*)data;
    ssize_t res;
    free(sock->sent.event);
    if (sock->sent.ep->ip.type == NABTO_IPV4) {
        struct sockaddr_in srv_addr;
        srv_addr.sin_family = AF_INET;
        srv_addr.sin_port = htons (sock->sent.ep->port);
//        srv_addr.sin_addr = sock->sent.ep->ip.v4.addr;
        memcpy((void*)&srv_addr.sin_addr,sock->sent.ep->ip.v4.addr, sizeof(srv_addr.sin_addr));
        res = sendto (sock->sock, sock->sent.buf, sock->sent.bufSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    } else { // IPv6
        struct sockaddr_in6 srv_addr;
        srv_addr.sin6_family = AF_INET6;
        srv_addr.sin6_port = htons (sock->sent.ep->port);
        memcpy((void*)&srv_addr.sin6_addr,sock->sent.ep->ip.v6.addr, sizeof(srv_addr.sin6_addr));
        res = sendto (sock->sock, sock->sent.buf, sock->sent.bufSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    }
    if (res < 0) {
        int status = errno;
        if (status == EAGAIN || EWOULDBLOCK) {
            // expected
        } else {
            NABTO_LOG_ERROR(NABTO_LOG_MODULE_UDP,"ERROR: (%i) '%s' in nm_epoll_event_send_to", strerror(status), (int) status);
            sock->sent.cb(NABTO_EC_FAILED_TO_SEND_PACKET, sock->sent.data);
            return;
        }
    }
    sock->sent.cb(NABTO_EC_OK, sock->sent.data);
    return;
}

void nm_epoll_async_send_to(nabto_udp_socket* socket, struct nabto_udp_endpoint* ep, uint8_t* buffer, uint16_t bufferSize, nabto_udp_packet_sent_callback cb, void* data)
{
    struct nabto_event* ne;
    ne = (struct nabto_event*)malloc(sizeof(struct nabto_event));
    socket->sent.event = ne;
    socket->sent.ep = ep;
    socket->sent.buf = buffer;
    socket->sent.bufSize = bufferSize;
    socket->sent.cb = cb;
    socket->sent.data = data;
    nabto_event_queue_post(pl, ne, nm_epoll_event_send_to, socket);
}

void nm_epoll_async_recv_from(nabto_udp_socket* socket, nabto_udp_packet_received_callback cb, void* data)
{
    struct nabto_event* ne;
    ne = (struct nabto_event*)malloc(sizeof(struct nabto_event));
    socket->recv.event = ne;
    socket->recv.cb = cb;
    socket->recv.data = data;
//    nabto_event_queue_post(pl, ne, nm_epoll_event_recv_from, socket);
}


