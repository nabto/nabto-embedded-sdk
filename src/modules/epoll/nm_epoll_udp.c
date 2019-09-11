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

struct nm_epoll_received_ctx {
    np_udp_packet_received_callback cb;
    void* data;
    struct np_event event;
};

struct np_udp_socket {
    enum nm_epoll_type type;
    struct np_platform* pl;
    int sock;
    bool isIpv6;
    bool destroyed;
    struct nm_epoll_created_ctx created;
    struct nm_epoll_received_ctx recv;
    struct np_event asyncRecvFromEvent;
};

static np_error_code nm_epoll_create(struct np_platform* pl, np_udp_socket** sock);
static void nm_epoll_destroy(np_udp_socket* sock);

static void nm_epoll_event_bind_mdns_ipv4(void* data);
static bool nm_epoll_init_mdns_ipv4_socket(int sock);
static void nm_epoll_async_bind_mdns_ipv4(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);

static void nm_epoll_event_bind_mdns_ipv6(void* data);
static bool nm_epoll_init_mdns_ipv6_socket(int sock);
static void nm_epoll_async_bind_mdns_ipv6(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);

/**
 * async functions implementing epoll functionallity for the udp
 * interface of <platform/udp.h> used in the np_platform.
 * Defined in .h file for testing purposes
 */
static void nm_epoll_async_bind(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);
static void nm_epoll_async_bind_port(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data);
static void nm_epoll_async_send_to(struct np_udp_send_context* ctx);
static void nm_epoll_async_recv_from(np_udp_socket* socket,
                              np_udp_packet_received_callback cb, void* data);
static enum np_ip_address_type nm_epoll_get_protocol(np_udp_socket* socket);
static size_t nm_epoll_get_local_ip( struct np_ip_address *addrs, size_t addrsSize);
static uint16_t nm_epoll_get_local_port(np_udp_socket* socket);
static void nm_epoll_udp_try_read(void* userData);

void nm_epoll_cancel_all_events(np_udp_socket* sock)
{
    NABTO_LOG_TRACE(LOG, "Cancelling all events");
    np_event_queue_cancel_event(sock->pl, &sock->created.event);
    np_event_queue_cancel_event(sock->pl, &sock->recv.event);
}

void nm_epoll_udp_init(struct nm_epoll_context* epoll, struct np_platform* pl)
{
    pl->udp.create      = &nm_epoll_create;
    pl->udp.destroy     = &nm_epoll_destroy;
    pl->udp.async_bind        = &nm_epoll_async_bind;
    pl->udp.async_bind_port   = &nm_epoll_async_bind_port;
    pl->udp.async_bind_mdns_ipv4 = &nm_epoll_async_bind_mdns_ipv4;
    pl->udp.async_bind_mdns_ipv6 = &nm_epoll_async_bind_mdns_ipv6;
    pl->udp.async_send_to     = &nm_epoll_async_send_to;
    pl->udp.async_recv_from   = &nm_epoll_async_recv_from;
    pl->udp.get_protocol      = &nm_epoll_get_protocol;
    pl->udp.get_local_ip      = &nm_epoll_get_local_ip;
    pl->udp.get_local_port    = &nm_epoll_get_local_port;
    pl->udpData = epoll;

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

void nm_epoll_udp_handle_event(np_udp_socket* sock, uint32_t events)
{
    // wait for last epoll event.
    if (sock->destroyed) {
        free(sock);
        return;
    }

    nm_epoll_udp_try_read(sock);
}

void nm_epoll_udp_try_read(void* userData)
{
    np_udp_socket* sock = userData;
    if (sock->recv.cb == NULL) {
        return;
    }
    struct np_udp_endpoint ep;
    struct np_platform* pl = sock->pl;
    struct nm_epoll_context* epoll = pl->udpData;
    ssize_t recvLength;
    uint8_t* start;
    start = pl->buf.start(epoll->recvBuffer);
    if (sock->isIpv6) {
        struct sockaddr_in6 sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, start,  pl->buf.size(epoll->recvBuffer), 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.v6.addr,&sa.sin6_addr.s6_addr, sizeof(ep.ip.v6.addr));
        ep.port = ntohs(sa.sin6_port);
        ep.ip.type = NABTO_IPV6;
    } else {
        struct sockaddr_in sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, start, pl->buf.size(epoll->recvBuffer), 0, (struct sockaddr*)&sa, &addrlen);
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
            NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_epoll_udp_handle_event", strerror(status), (int) status);
            if(sock->recv.cb) {
                cb = sock->recv.cb;
                sock->recv.cb = NULL;
                cb(NABTO_EC_UDP_SOCKET_ERROR, ep, NULL, 0, sock->recv.data);
            }
            return;
        }
    }
    if (sock->recv.cb) {
        np_udp_packet_received_callback cb = sock->recv.cb;
        sock->recv.cb = NULL;
        cb(NABTO_EC_OK, ep, pl->buf.start(epoll->recvBuffer), recvLength, sock->recv.data);
    }
    nm_epoll_udp_try_read(sock);
}

void nm_epoll_event_bind(void* data)
{
    np_udp_socket* us = (np_udp_socket*)data;
    struct nm_epoll_context* epoll = us->pl->udpData;
    us->sock = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (us->sock == -1) {
        us->sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (us->sock == -1) {
            np_error_code ec;
            NABTO_LOG_ERROR(LOG, "Unable to create socket: (%i) '%s'.", errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR;
            us->created.cb(ec, us->created.data);
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
            us->created.cb(ec, us->created.data);
            nm_epoll_cancel_all_events(us);
            free(us);
            return;
        }
    }
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = us;
    if (epoll_ctl(epoll->fd, EPOLL_CTL_ADD, us->sock, &ev) == -1) {
        NABTO_LOG_FATAL(LOG,"could not add file descriptor to epoll set: (%i) '%s'", errno, strerror(errno));
        close(us->sock);
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, us->created.data);
        nm_epoll_cancel_all_events(us);
        free(us);
        return;
    }
    us->created.cb(NABTO_EC_OK, us->created.data);
    return;
}

np_error_code nm_epoll_create(struct np_platform* pl, np_udp_socket** sock)
{
    *sock = calloc(1, sizeof(np_udp_socket));
    (*sock)->type = NM_EPOLL_TYPE_UDP;
    (*sock)->pl = pl;
    return NABTO_EC_OK;
}

void nm_epoll_async_bind(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data)
{
    struct np_platform* pl = sock->pl;
    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, &nm_epoll_event_bind, sock);
}


void nm_epoll_destroy(np_udp_socket* sock)
{
    if (sock == NULL) {
        return;
    }
    struct nm_epoll_context* epoll = sock->pl->udpData;
    shutdown(sock->sock, SHUT_RDWR);

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = NULL;

    // set data ptr to NULL such that we do not tri to use the ptr in the future.
    epoll_ctl(epoll->fd, EPOLL_CTL_MOD, sock->sock, &ev);

    if (epoll_ctl(epoll->fd, EPOLL_CTL_DEL, sock->sock, NULL) == -1) {
        NABTO_LOG_ERROR(LOG,"Cannot remove fd from epoll set, %i: %s", errno, strerror(errno));
    }
    close(sock->sock);
    nm_epoll_cancel_all_events(sock);
    sock->destroyed = true;
    //free(sock);
}

void nm_epoll_event_bind_port(void* data)
{
    np_udp_socket* us = (np_udp_socket*)data;
    struct nm_epoll_context* epoll = us->pl->udpData;
    struct epoll_event* ev;

    us->sock = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (us->sock == -1) {
        us->sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (us->sock == -1) {
            np_error_code ec;
            NABTO_LOG_ERROR(LOG, "Unable to create socket: (%i) '%s'.", errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR;
            us->created.cb(ec, us->created.data);
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
            us->created.cb(ec, us->created.data);
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
        us->created.cb(ec, us->created.data);
        nm_epoll_cancel_all_events(us);
        free(us);
        return;
    }
    ev = (struct epoll_event*)malloc(sizeof(struct epoll_event));
    ev->events = EPOLLIN | EPOLLET;
    ev->data.ptr = us;
    if (epoll_ctl(epoll->fd, EPOLL_CTL_ADD, us->sock, ev) == -1) {
        NABTO_LOG_FATAL(LOG,"could not add file descriptor to epoll set: (%i) '%s'", errno, strerror(errno));
        close(us->sock);
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, us->created.data);
        nm_epoll_cancel_all_events(us);
        free(us);
        return;
    }
    us->created.cb(NABTO_EC_OK, us->created.data);
    return;

}

void nm_epoll_async_bind_port(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data)
{
    struct np_platform* pl = sock->pl;
    sock->created.cb = cb;
    sock->created.data = data;
    sock->created.port = port;
    np_event_queue_post(pl, &sock->created.event, nm_epoll_event_bind_port, sock);
}


void nm_epoll_async_bind_mdns_ipv4(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data)
{
    struct np_platform* pl = sock->pl;
    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, nm_epoll_event_bind_mdns_ipv4, sock);
}

void nm_epoll_event_bind_mdns_ipv4(void* data)
{
    np_udp_socket* us = (np_udp_socket*)data;
    struct nm_epoll_context* epoll = us->pl->udpData;
    us->sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (us->sock < 0) {
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, us->created.data);
        free(us);
    }
    us->isIpv6 = false;

    // TODO test return value
    if (!nm_epoll_init_mdns_ipv4_socket(us->sock)) {
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, us->created.data);
        close(us->sock);
        nm_epoll_cancel_all_events(us);
        free(us);
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = us;
    if (epoll_ctl(epoll->fd, EPOLL_CTL_ADD, us->sock, &ev) == -1) {
        NABTO_LOG_FATAL(LOG,"could not add file descriptor to epoll set: (%i) '%s'", errno, strerror(errno));
        close(us->sock);
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, us->created.data);
        nm_epoll_cancel_all_events(us);
        free(us);
        return;
    }
    us->created.cb(NABTO_EC_OK, us->created.data);
    return;
}

bool nm_epoll_init_mdns_ipv4_socket(int sock)
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

    struct sockaddr_in si_me;
    memset(&si_me, 0, sizeof(si_me));
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(5353);
    si_me.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr*)&si_me, sizeof(si_me)) < 0) {
        return false;
    }

    {
        struct ifaddrs* interfaces = NULL;
        if (getifaddrs(&interfaces) == 0) {

            struct ifaddrs* iterator = interfaces;
            while (iterator != NULL) {
                if (iterator->ifa_addr->sa_family == AF_INET) {
                    struct ip_mreq group;
                    memset(&group, 0, sizeof(struct ip_mreq));
                    group.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
                    struct sockaddr_in* in = (struct sockaddr_in*)iterator->ifa_addr;
                    group.imr_interface = in->sin_addr;
                    int status = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group));
                    if (status < 0) {
                        NABTO_LOG_ERROR(LOG, "Cannot add ip membership %d", errno);
                    }

                }

                iterator = iterator->ifa_next;
            }
            freeifaddrs(interfaces);
        }
    }
    return true;
}

void nm_epoll_async_bind_mdns_ipv6(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data)
{
    struct np_platform* pl = sock->pl;
    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, nm_epoll_event_bind_mdns_ipv6, sock);
}

void nm_epoll_event_bind_mdns_ipv6(void* data)
{
    np_udp_socket* us = (np_udp_socket*)data;
    struct nm_epoll_context* epoll = us->pl->udpData;
    us->sock = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (us->sock < 0) {
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, us->created.data);
        free(us);
    }
    us->isIpv6 = true;

    // TODO test return value
    if (!nm_epoll_init_mdns_ipv6_socket(us->sock)) {
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, us->created.data);
        close(us->sock);
        nm_epoll_cancel_all_events(us);
        free(us);
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = us;
    if (epoll_ctl(epoll->fd, EPOLL_CTL_ADD, us->sock, &ev) == -1) {
        NABTO_LOG_FATAL(LOG,"could not add file descriptor to epoll set: (%i) '%s'", errno, strerror(errno));
        close(us->sock);
        us->created.cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, us->created.data);
        nm_epoll_cancel_all_events(us);
        free(us);
        return;
    }
    us->created.cb(NABTO_EC_OK, us->created.data);
    return;
}

bool nm_epoll_init_mdns_ipv6_socket(int sock)
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
                    int status = setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&group, sizeof(struct ipv6_mreq));
                    if (status < 0) {
                        NABTO_LOG_ERROR(LOG, "Cannot add ipv6 membership %d", errno);
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
        res = sendto (sock->sock, ctx->buffer, ctx->bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    } else { // IPv6
        struct sockaddr_in6 srv_addr;
        srv_addr.sin6_family = AF_INET6;
        srv_addr.sin6_flowinfo = 0;
        srv_addr.sin6_scope_id = 0;
        srv_addr.sin6_port = htons (ctx->ep.port);
        memcpy((void*)&srv_addr.sin6_addr,ctx->ep.ip.v6.addr, sizeof(srv_addr.sin6_addr));
        res = sendto (sock->sock, ctx->buffer, ctx->bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
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
    struct np_platform* pl = ctx->sock->pl;
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
    struct np_platform* pl = socket->pl;

    socket->recv.cb = cb;
    socket->recv.data = data;

    np_event_queue_post(pl, &socket->asyncRecvFromEvent, nm_epoll_udp_try_read, socket);
}
