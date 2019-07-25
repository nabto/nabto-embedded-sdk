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
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>

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
};

static int nm_epoll_fd = -1;
static struct np_platform* pl = 0;
static np_communication_buffer* recv_buf;
struct epoll_event events[64];

/**
 * Handles events from epoll_wait
 */
void nm_epoll_handle_event(np_udp_socket* sock); // consider an np_epoll_event type instead of reusing the socket structure

static void nm_epoll_event_create_mdns(void* data);
static bool nm_epoll_init_mdns_socket(int sock);
static void nm_epoll_async_create_mdns(np_udp_socket_created_callback cb, void* data);

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

void np_udp_init(struct np_platform* pl_in) {
    if(!pl_in) {
        NABTO_LOG_FATAL(LOG, "No np_platform provided");
        return;
    }
    pl = pl_in;
    pl->udp.async_create      = &nm_epoll_async_create;
    pl->udp.async_bind_port   = &nm_epoll_async_bind_port;
    pl->udp.async_create_mdns = &nm_epoll_async_create_mdns;
    pl->udp.async_send_to     = &nm_epoll_async_send_to;
    pl->udp.async_recv_from   = &nm_epoll_async_recv_from;
    pl->udp.get_protocol      = &nm_epoll_get_protocol;
    pl->udp.get_local_ip      = &nm_epoll_get_local_ip;
    pl->udp.get_local_port    = &nm_epoll_get_local_port;
    pl->udp.async_destroy     = &nm_epoll_async_destroy;
    pl->udp.inf_wait          = &nm_epoll_inf_wait;
    pl->udp.timed_wait        = &nm_epoll_timed_wait;
    pl->udp.read              = &nm_epoll_read;

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

size_t nm_epoll_get_local_ip( struct np_ip_address *addrs, size_t addrsSize)
{
    struct sockaddr_in si_me, si_other;
    struct sockaddr_in6 si6_me, si6_other;
    struct in_addr v4any;
    struct in6_addr v6any;
    size_t ind = 0;

    v4any.s_addr = INADDR_ANY;
    v6any = in6addr_any;
    if (addrsSize < 1) {
        return 0;
    }
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s != -1) {
        memset(&si_me, 0, sizeof(si_me));
        memset(&si_other, 0, sizeof(si_me));
        //bind to local port 4567
        si_me.sin_family = AF_INET;
        si_me.sin_port = htons(4567);
        si_me.sin_addr.s_addr = INADDR_ANY;

        //"connect" google's DNS server at 8.8.8.8 , port 4567
        si_other.sin_family = AF_INET;
        si_other.sin_port = htons(4567);
        si_other.sin_addr.s_addr = inet_addr("8.8.8.8");
        if(connect(s,(struct sockaddr*)&si_other,sizeof(si_other)) == -1) {
            // This is expected if the device does not have ipv4 access
            // NABTO_LOG_ERROR(LOG, "Cannot connect to host");
        } else {
            struct sockaddr_in my_addr;
            socklen_t len = sizeof my_addr;
            if(getsockname(s,(struct sockaddr*)&my_addr,&len) == -1) {
                NABTO_LOG_ERROR(LOG, "getsockname failed");
            } else {
                if (memcmp(&my_addr.sin_addr, &v4any, 4) != 0) {
                    addrs[ind].type = NABTO_IPV4;
                    memcpy(addrs[ind].v4.addr, &my_addr.sin_addr.s_addr, 4);
                    ind++;
                }
            }
        }
        close(s);
    }
    if (addrsSize < ind+1) {
        return ind;
    }
    s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s != -1) {
        memset(&si6_me, 0, sizeof(si6_me));
        memset(&si6_other, 0, sizeof(si6_me));
        //bind to local port 4567
        si6_me.sin6_family = AF_INET6;
        si6_me.sin6_port = htons(4567);
        si6_me.sin6_addr = in6addr_any;

        //"connect" google's DNS server at 2001:4860:4860::8888 , port 4567
        si6_other.sin6_family = AF_INET6;
        si6_other.sin6_port = htons(4567);
        inet_pton(AF_INET6, "2001:4860:4860::8888", si6_other.sin6_addr.s6_addr);
        if(connect(s,(struct sockaddr*)&si6_other,sizeof(si6_other)) == -1) {
            // this is expected if the host does not have a public ipv6 address.
            // NABTO_LOG_ERROR(LOG, "Cannot connect to host");
        } else {
            struct sockaddr_in6 my_addr;
            socklen_t len = sizeof my_addr;
            if(getsockname(s,(struct sockaddr*)&my_addr,&len) == -1) {
                NABTO_LOG_ERROR(LOG, "getsockname failed");
            } else {
                if (memcmp(&my_addr.sin6_addr, &v6any, 16) != 0) {
                    addrs[ind].type = NABTO_IPV6;
                    memcpy(addrs[ind].v6.addr, my_addr.sin6_addr.s6_addr, 16);
                    ind++;
                }
            }
        }
        close(s);
    }
    return ind;
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

int nm_epoll_timed_wait(uint32_t ms)
{
    int nfds;
//    NABTO_LOG_TRACE(LOG, "waits for %u ms", ms);
    nfds = epoll_wait(nm_epoll_fd, events, 64, ms);
    if (nfds < 0) {
        NABTO_LOG_ERROR(LOG, "Error in epoll wait: (%i) '%s'", errno, strerror(errno));
    }
//    NABTO_LOG_TRACE(LOG, "epoll_wait returned with %i file descriptors", nfds);
    return nfds;
}

int nm_epoll_inf_wait()
{
    int nfds;
//        NABTO_LOG_TRACE(LOG, "epoll waits forever");
    nfds = epoll_wait(nm_epoll_fd, events, 64, -1);
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
        if (status == EAGAIN || status == EWOULDBLOCK) {
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
        NABTO_LOG_TRACE(LOG, "received %i bytes of data data, invoking callback", recvLength);
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
    socket->des.cb = cb;
    socket->des.data = data;
    np_event_queue_post(pl, &socket->des.event, nm_epoll_event_destroy, socket);

}

void nm_epoll_event_bind_port(void* data)
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
    int i;
    if(us->isIpv6) {
        struct sockaddr_in6 si_me6;
        memset(&si_me6, 0, sizeof(si_me6));
        si_me6.sin6_family = AF_INET6;
        si_me6.sin6_port = htons(us->created.port);
        si_me6.sin6_addr = in6addr_any;
        i = bind(us->sock, (struct sockaddr*)&si_me6, sizeof(si_me6));
        NABTO_LOG_INFO(LOG, "bind returned %i", i);
    } else {
        struct sockaddr_in si_me;
        memset(&si_me, 0, sizeof(si_me));
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

void nm_epoll_async_bind_port(uint16_t port, np_udp_socket_created_callback cb, void* data)
{
    np_udp_socket* sock;
    sock = (np_udp_socket*)malloc(sizeof(np_udp_socket));
    sock->created.cb = cb;
    sock->created.data = data;
    sock->created.port = port;
    np_event_queue_post(pl, &sock->created.event, nm_epoll_event_bind_port, sock);
}


void nm_epoll_async_create_mdns(np_udp_socket_created_callback cb, void* data)
{
    np_udp_socket* sock;
    sock = (np_udp_socket*)malloc(sizeof(np_udp_socket));
    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, nm_epoll_event_create_mdns, sock);
}

void nm_epoll_event_create_mdns(void* data)
{
    np_udp_socket* us = (np_udp_socket*)data;
    us->sock = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (us->sock < 0) {
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, NULL, us->created.data);
        free(us);
    }
    us->isIpv6 = true;

    // TODO test return value
    if (!nm_epoll_init_mdns_socket(us->sock)) {
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, NULL, us->created.data);
        close(us->sock);
        nm_epoll_cancel_all_events(us);
        free(us);
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = us;
    if (epoll_ctl(nm_epoll_fd, EPOLL_CTL_ADD, us->sock, &ev) == -1) {
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

bool nm_epoll_init_mdns_socket(int sock)
{
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
        return false;
    }

#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) {
        return false;
    }
#endif

    struct sockaddr_in6 si_me;
    memset(&si_me, 0, sizeof(si_me));
    si_me.sin6_family = AF_INET6;
    si_me.sin6_port = htons(5353);
    si_me.sin6_addr = in6addr_any;
    if (bind(sock, (struct sockaddr*)&si_me, sizeof(si_me)) < 0) {
        return false;
    }

    {
        struct ifaddrs* interfaces = NULL;
        if (getifaddrs(&interfaces) == 0) {

            struct ifaddrs* iterator = interfaces;
            while (iterator != NULL) {

                int index = if_nametoindex(iterator->ifa_name);
                {
                    struct ipv6_mreq group;
                    memset(&group, 0, sizeof(struct ipv6_mreq));
                    inet_pton(AF_INET6, "ff02::fb", &group.ipv6mr_multiaddr);
                    group.ipv6mr_interface = index;
                    if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&group, sizeof(struct ipv6_mreq)) < 0) {
                        // todo log warning.
                    }
                }

                if (iterator->ifa_addr->sa_family == AF_INET) {
                    struct ip_mreq group;
                    memset(&group, 0, sizeof(struct ip_mreq));
                    group.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
                    struct sockaddr_in* in = (struct sockaddr_in*)iterator->ifa_addr;
                    group.imr_interface = in->sin_addr;
                    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) < 0) {
                        // TODO log warning
                    }

                }

                iterator = iterator->ifa_next;
            }
            freeifaddrs(interfaces);
        }
    }
    return true;
}

void nm_epoll_event_send_to(void* data)
{
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
            return;
        }
    }
    if (ctx->cb) {
        ctx->cb(NABTO_EC_OK, ctx->cbData);
    }
    return;
}

void nm_epoll_async_send_to(struct np_udp_send_context* ctx)
{
    bool status = np_event_queue_post(pl, &ctx->ev, nm_epoll_event_send_to, ctx);

    if (status) {
        NABTO_LOG_TRACE(LOG, "nm_epoll_async_send_to canceled event");
    }



    if (!np_event_queue_is_event_enqueued(pl, &ctx->ev)) {
        NABTO_LOG_ERROR(LOG, "the event should be enqueued");
    }
}

void nm_epoll_async_recv_from(np_udp_socket* socket,
                              np_udp_packet_received_callback cb, void* data)
{
    socket->recv.cb = cb;
    socket->recv.data = data;
}
