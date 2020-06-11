#include "nm_select_unix_udp.h"

#include <platform/np_logging.h>
#include <platform/np_util.h>
#include <platform/np_completion_event.h>

#include <stdlib.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

#define LOG NABTO_LOG_MODULE_UDP

/**
 * Helper function declarations
 */
static void nm_select_unix_udp_handle_event(struct np_udp_socket* sock);
static void nm_select_unix_udp_free_socket(struct np_udp_socket* sock);

/**
 * Api function declarations
 */
static np_error_code nm_select_unix_udp_create(struct np_udp* obj, struct np_udp_socket** sock);
static void nm_select_unix_udp_destroy(struct np_udp_socket* sock);
static void nm_select_unix_udp_abort(struct np_udp_socket* sock);
static void nm_select_unix_udp_async_bind_port(struct np_udp_socket* sock, uint16_t port, struct np_completion_event* completionEvent);
static void nm_select_unix_async_bind_mdns_ipv4(struct np_udp_socket* sock, struct np_completion_event* completionEvent);
static void nm_select_unix_async_bind_mdns_ipv6(struct np_udp_socket* sock, struct np_completion_event* completionEvent);
static void nm_select_unix_udp_async_send_to(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                             uint8_t* buffer, uint16_t bufferSize,
                                             struct np_completion_event* completionEvent);
static void nm_select_unix_udp_async_recv_wait(struct np_udp_socket* socket, struct np_completion_event* completionEvent);
static np_error_code nm_select_unix_udp_recv_from(struct np_udp_socket* socket, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength);
static uint16_t nm_select_unix_udp_get_local_port(struct np_udp_socket* socket);

static np_error_code udp_send_to(struct np_udp_socket* s, const struct np_udp_endpoint* ep, const uint8_t* buffer, uint16_t bufferSize);
static np_error_code udp_recv_from(struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength);
static np_error_code bind_port(struct np_udp_socket* s, uint16_t port);
static uint16_t get_local_port(struct np_udp_socket* s);
static np_error_code create_socket_any(struct np_udp_socket* s);
static np_error_code create_socket_ipv6(struct np_udp_socket* s);
static np_error_code create_socket_ipv4(struct np_udp_socket* s);
static bool init_mdns_ipv6_socket(int sock);
static bool init_mdns_ipv4_socket(int sock);
static void mdns_update_ipv4_socket_registration(int sock);
static void mdns_update_ipv6_socket_registration(int sock);



static struct np_udp_functions vtable = {
    .create           = &nm_select_unix_udp_create,
    .destroy          = &nm_select_unix_udp_destroy,
    .abort            = &nm_select_unix_udp_abort,
    .async_bind_port  = &nm_select_unix_udp_async_bind_port,
    .async_bind_mdns_ipv4 = &nm_select_unix_async_bind_mdns_ipv4,
    .async_bind_mdns_ipv6 = &nm_select_unix_async_bind_mdns_ipv6,
    .async_send_to    = &nm_select_unix_udp_async_send_to,
    .async_recv_wait  = &nm_select_unix_udp_async_recv_wait,
    .recv_from        = &nm_select_unix_udp_recv_from,
    .get_local_port   = &nm_select_unix_udp_get_local_port
};


struct np_udp nm_select_unix_udp_get_impl(struct nm_select_unix* ctx)
{
    struct np_udp obj;
    obj.vptr = &vtable;
    obj.data = ctx;
    return obj;
}

np_error_code nm_select_unix_udp_create(struct np_udp* obj, struct np_udp_socket** sock)
{
    struct np_udp_socket* s = calloc(1, sizeof(struct np_udp_socket));
    if (!s) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    *sock = s;
    s->sock = -1;

    struct nm_select_unix* selectCtx = obj->data;

    s->selectCtx = selectCtx;
    s->aborted = false;

    nn_llist_append(&selectCtx->udpSockets, &s->udpSocketsNode, s);

    // add fd to select fd set.
    nm_select_unix_notify(selectCtx);

    return NABTO_EC_OK;
}

np_error_code nm_select_unix_udp_async_bind_port_ec(struct np_udp_socket* sock, uint16_t port)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec;

    ec = create_socket_any(sock);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = bind_port(sock, port);
    if (ec != NABTO_EC_OK) {
        close(sock->sock);
    }

    return NABTO_EC_OK;
}

void nm_select_unix_udp_async_bind_port(struct np_udp_socket* sock, uint16_t port, struct np_completion_event* completionEvent)
{
    np_error_code ec = nm_select_unix_udp_async_bind_port_ec(sock, port);
    np_completion_event_resolve(completionEvent, ec);
}

np_error_code nm_select_unix_async_bind_mdns_ipv4_ec(struct np_udp_socket* sock)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec;
    ec = create_socket_ipv4(sock);

    if (ec != NABTO_EC_OK) {
        return ec;
    }

    if (!init_mdns_ipv4_socket(sock->sock)) {
        close(sock->sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    mdns_update_ipv4_socket_registration(sock->sock);

    return NABTO_EC_OK;
}

void nm_select_unix_async_bind_mdns_ipv4(struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    np_error_code ec = nm_select_unix_async_bind_mdns_ipv4_ec(sock);
    np_completion_event_resolve(completionEvent, ec);
}

np_error_code nm_select_unix_async_bind_mdns_ipv6_ec(struct np_udp_socket* sock)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec = create_socket_ipv6(sock);
    if (ec) {
        return ec;
    }

    int no = 0;
    int status = setsockopt(sock->sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no));
    if (status < 0)
    {
        NABTO_LOG_ERROR(LOG, "Cannot set IPV6_V6ONLY");
    }

    if (!init_mdns_ipv6_socket(sock->sock)) {
        close(sock->sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    mdns_update_ipv6_socket_registration(sock->sock);

    return NABTO_EC_OK;
}

void nm_select_unix_async_bind_mdns_ipv6(struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    np_error_code ec = nm_select_unix_async_bind_mdns_ipv6_ec(sock);
    np_completion_event_resolve(completionEvent, ec);
}

np_error_code nm_select_unix_udp_async_send_to_ec(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                                  uint8_t* buffer, uint16_t bufferSize)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "send to called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec = udp_send_to(sock, ep, buffer, bufferSize);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    return NABTO_EC_OK;
}

void nm_select_unix_udp_async_send_to(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                      uint8_t* buffer, uint16_t bufferSize,
                                      struct np_completion_event* completionEvent)
{
    np_error_code ec = nm_select_unix_udp_async_send_to_ec(sock, ep, buffer, bufferSize);
    np_completion_event_resolve(completionEvent, ec);
}


void nm_select_unix_udp_async_recv_wait(struct np_udp_socket* sock,
                                        struct np_completion_event* completionEvent)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "recv from called on aborted socket");
        np_completion_event_resolve(completionEvent, NABTO_EC_ABORTED);
        return;
    }

    if (sock->recv.completionEvent != NULL) {
        NABTO_LOG_ERROR(LOG, "operation already in progress");
        np_completion_event_resolve(completionEvent, NABTO_EC_OPERATION_IN_PROGRESS);
        return;
    }

    sock->recv.completionEvent = completionEvent;
    nm_select_unix_notify(sock->selectCtx);
    return;
}

np_error_code nm_select_unix_udp_recv_from(struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength)
{
    return udp_recv_from(sock, ep, buffer, bufferSize, readLength);
}

uint16_t nm_select_unix_udp_get_local_port(struct np_udp_socket* sock)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "get local port called on aborted socket");
        return 0;
    }
    return get_local_port(sock);
}

void nm_select_unix_udp_abort(struct np_udp_socket* sock)
{
    if (!sock->aborted) {
        sock->aborted = true;
    }

    if (sock->recv.completionEvent != NULL) {
        struct np_completion_event* ev = sock->recv.completionEvent;
        sock->recv.completionEvent = NULL;
        np_completion_event_resolve(ev, NABTO_EC_ABORTED);
    }
}

void nm_select_unix_udp_destroy(struct np_udp_socket* sock)
{
    if (sock == NULL) {
        return;
    }
    nm_select_unix_udp_free_socket(sock);
    return;
}

void nm_select_unix_udp_handle_event(struct np_udp_socket* sock)
{
    if (sock->recv.completionEvent != NULL) {
        struct np_completion_event* ev = sock->recv.completionEvent;
        sock->recv.completionEvent = NULL;
        np_completion_event_resolve(ev, NABTO_EC_OK);
    }
}

void nm_select_unix_udp_free_socket(struct np_udp_socket* sock)
{
    nn_llist_erase_node(&sock->udpSocketsNode);

    nm_select_unix_udp_abort(sock);
    shutdown(sock->sock, SHUT_RDWR);
    close(sock->sock);
    free(sock);
}

void nm_select_unix_udp_build_fd_sets(struct nm_select_unix* ctx)
{
    struct np_udp_socket* s;

    NN_LLIST_FOREACH(s, &ctx->udpSockets)
    {
        if (s->recv.completionEvent && s->sock != -1) {
            FD_SET(s->sock, &ctx->readFds);
            ctx->maxReadFd = NP_MAX(ctx->maxReadFd, s->sock);
        }
    }
}

void nm_select_unix_udp_handle_select(struct nm_select_unix* ctx, int nfds)
{
    struct np_udp_socket* s;

    NN_LLIST_FOREACH(s, &ctx->udpSockets)
    {
        if (s->sock != -1 && FD_ISSET(s->sock, &ctx->readFds)) {
            nm_select_unix_udp_handle_event(s);
        }
    }
}


int nonblocking_socket(int domain, int type)
{
#if defined(SOCK_NONBLOCK)
    return socket(domain, type | SOCK_NONBLOCK, 0);
#endif

#ifdef F_GETFL
    int sock = socket(domain, type, 0);

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) flags = 0;
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    return sock;
#endif
}

np_error_code udp_send_to(struct np_udp_socket* s, const struct np_udp_endpoint* ep, const uint8_t* buffer, uint16_t bufferSize)
{
    ssize_t res;

    struct np_ip_address sendIp;

    if (s->type == ep->ip.type) {
        // No conversion needed.
        sendIp = ep->ip;
    } else if (s->type == NABTO_IPV6 && ep->ip.type == NABTO_IPV4) {
        // convert ipv4 to ipv6 mapped ipv4
        np_ip_convert_v4_to_v4_mapped(&ep->ip, &sendIp);
    } else if (s->type == NABTO_IPV4 && np_ip_is_v4_mapped(&ep->ip)) {
        np_ip_convert_v4_mapped_to_v4(&ep->ip, &sendIp);
    } else {
        NABTO_LOG_TRACE(LOG, "Cannot send ipv6 packets on an ipv4 socket.");
        return NABTO_EC_FAILED_TO_SEND_PACKET;
    }

    NABTO_LOG_TRACE(LOG, "Sending packet of size %d, to %s:%d", bufferSize, np_ip_address_to_string(&sendIp), ep->port);
    if (sendIp.type == NABTO_IPV4) {
        struct sockaddr_in srv_addr;
        srv_addr.sin_family = AF_INET;
        srv_addr.sin_port = htons (ep->port);
        memcpy((void*)&srv_addr.sin_addr, sendIp.ip.v4, sizeof(srv_addr.sin_addr));
        res = sendto (s->sock, buffer, bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    } else { // IPv6
        struct sockaddr_in6 srv_addr;
        srv_addr.sin6_family = AF_INET6;
        srv_addr.sin6_flowinfo = 0;
        srv_addr.sin6_scope_id = 0;
        srv_addr.sin6_port = htons (ep->port);
        memcpy((void*)&srv_addr.sin6_addr,sendIp.ip.v6, sizeof(srv_addr.sin6_addr));
        res = sendto (s->sock, buffer, bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    }

    if (res < 0) {
        int status = errno;
        NABTO_LOG_TRACE(LOG, "UDP returned error status (%d) %s", status, strerror(status));
        if (status == EAGAIN || status == EWOULDBLOCK) {
            // expected
            // just drop the packet and the upper layers will take care of retransmissions.
        } else {

            if (status == EADDRNOTAVAIL || // if we send to ipv6 scopes we do not have
                status == ENETUNREACH || // if we send ipv6 on a system without it.
                status == EAFNOSUPPORT) // if we send ipv6 on an ipv4 only socket
            {
                NABTO_LOG_TRACE(LOG,"ERROR: (%i) '%s' in nm_epoll_event_send_to", (int) status, strerror(status));
            } else {
                NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_epoll_event_send_to", (int) status, strerror(status));
            }
            return NABTO_EC_FAILED_TO_SEND_PACKET;
        }
    }

    return NABTO_EC_OK;
}

np_error_code udp_recv_from(struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength)
{
    ssize_t recvLength;
    if (sock->type == NABTO_IPV6) {
        struct sockaddr_in6 sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, buffer, bufferSize, 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep->ip.ip.v6, &sa.sin6_addr.s6_addr, sizeof(ep->ip.ip.v6));
        ep->port = ntohs(sa.sin6_port);
        ep->ip.type = NABTO_IPV6;
    } else {
        struct sockaddr_in sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, buffer, bufferSize, 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep->ip.ip.v4, &sa.sin_addr.s_addr, sizeof(ep->ip.ip.v4));
        ep->port = ntohs(sa.sin_port);
        ep->ip.type = NABTO_IPV4;
    }
    if (recvLength < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK) {
            // expected
            // wait for next event to check for data.
            return NABTO_EC_AGAIN;
        } else {
            NABTO_LOG_ERROR(LOG,"ERROR: (%d) '%s' in udp_recv_from", status, strerror(status));
            return NABTO_EC_UDP_SOCKET_ERROR;
        }
    }
    *readLength = recvLength;
    return NABTO_EC_OK;
}

np_error_code bind_port(struct np_udp_socket* s, uint16_t port)
{
    int status;

    if (s->type == NABTO_IPV6) {
        struct sockaddr_in6 si_me6;
        memset(&si_me6, 0, sizeof(si_me6));
        si_me6.sin6_family = AF_INET6;
        si_me6.sin6_port = htons(port);
        si_me6.sin6_addr = in6addr_any;
        status = bind(s->sock, (struct sockaddr*)&si_me6, sizeof(si_me6));
    } else {
        struct sockaddr_in si_me;
        memset(&si_me, 0, sizeof(si_me));
        si_me.sin_family = AF_INET;
        si_me.sin_port = htons(port);
        si_me.sin_addr.s_addr = INADDR_ANY;
        status = bind(s->sock, (struct sockaddr*)&si_me, sizeof(si_me));
    }

    NABTO_LOG_TRACE(LOG, "bind returned %i", status);

    if (status == 0) {
        return NABTO_EC_OK;
    } else {
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }
}

uint16_t get_local_port(struct np_udp_socket* s)
{
    if (s->type == NABTO_IPV6) {
        struct sockaddr_in6 addr;
        addr.sin6_port = 0;
        socklen_t length = sizeof(struct sockaddr_in6);
        getsockname(s->sock, (struct sockaddr*)(&addr), &length);
        return htons(addr.sin6_port);
    } else {
        struct sockaddr_in addr;
        addr.sin_port = 0;
        socklen_t length = sizeof(struct sockaddr_in);
        getsockname(s->sock, (struct sockaddr*)(&addr), &length);
        return htons(addr.sin_port);
    }
}

np_error_code create_socket_any(struct np_udp_socket* s)
{
    int sock = nonblocking_socket(AF_INET6, SOCK_DGRAM);
    if (sock == -1) {
        sock = nonblocking_socket(AF_INET, SOCK_DGRAM);
        if (s->sock == -1) {
            int e = errno;
            NABTO_LOG_ERROR(LOG, "Unable to create socket: (%i) '%s'.", e, strerror(e));
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        } else {
            NABTO_LOG_WARN(LOG, "IPv4 socket opened since IPv6 socket creation failed");
            s->type = NABTO_IPV4;
        }
    } else {
        int no = 0;
        s->type = NABTO_IPV6;
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no)))
        {
            int e = errno;
            NABTO_LOG_ERROR(LOG,"Unable to set option: (%i) '%s'.", e, strerror(e));

            close(s->sock);
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        }
    }
    s->sock = sock;
    return NABTO_EC_OK;
}

np_error_code create_socket_ipv6(struct np_udp_socket* s)
{
    int sock = nonblocking_socket(AF_INET6, SOCK_DGRAM);
    if (sock == -1) {
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    int no = 0;
    int status = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no));
    if (status < 0) {
        NABTO_LOG_ERROR(LOG, "Cannot set IPV6_V6ONLY");
    }

    s->type = NABTO_IPV6;
    s->sock = sock;
    return NABTO_EC_OK;
}

np_error_code create_socket_ipv4(struct np_udp_socket* s)
{
    int sock = nonblocking_socket(AF_INET, SOCK_DGRAM);
    if (sock == -1) {
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }
    s->type = NABTO_IPV4;
    s->sock = sock;
    return NABTO_EC_OK;
}

bool init_mdns_ipv6_socket(int sock)
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
        NABTO_LOG_INFO(LOG, "bind mdns ipv6 failed (%d) %s", errno, strerror(errno));
        return false;
    }

    struct ipv6_mreq group;
    memset(&group, 0, sizeof(struct ipv6_mreq));
    inet_pton(AF_INET6, "ff02::fb", &group.ipv6mr_multiaddr);
    group.ipv6mr_interface = 0;
    int status = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&group, sizeof(struct ipv6_mreq));
    if (status < 0) {
        NABTO_LOG_ERROR(LOG, "Cannot add ipv6 default membership %d", errno);
    }

    return true;
}


bool init_mdns_ipv4_socket(int sock)
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

    struct ip_mreq group;
    memset(&group, 0, sizeof(struct ip_mreq));
    group.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
    group.imr_interface.s_addr = INADDR_ANY;
    int status = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group));
    if (status < 0) {
        NABTO_LOG_ERROR(LOG, "Cannot add ipv4 default membership %d", errno);
    }

    return true;
}

void mdns_update_ipv4_socket_registration(int sock)
{
    struct ifaddrs* interfaces = NULL;
    if (getifaddrs(&interfaces) == 0) {

        struct ifaddrs* iterator = interfaces;
        while (iterator != NULL) {
            if (iterator->ifa_addr != NULL) {
                struct ip_mreqn group;
                memset(&group, 0, sizeof(struct ip_mreq));
                group.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
                //struct sockaddr_in* in = (struct sockaddr_in*)iterator->ifa_addr;
                int index = if_nametoindex(iterator->ifa_name);
                group.imr_ifindex = index;
                int status = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group));
                if (status < 0) {
                    if (errno == EADDRINUSE) {
                        // ok probable already registered
                    } else {
                        NABTO_LOG_TRACE(LOG, "Cannot add ipv4 membership %d interface %s", errno, iterator->ifa_name);
                    }
                }

            }

            iterator = iterator->ifa_next;
        }
        freeifaddrs(interfaces);
    }
}

void mdns_update_ipv6_socket_registration(int sock)
{
    struct ifaddrs* interfaces = NULL;
    if (getifaddrs(&interfaces) == 0) {

        struct ifaddrs* iterator = interfaces;
        while (iterator != NULL) {
            if (iterator->ifa_addr != NULL)
            {
                int index = if_nametoindex(iterator->ifa_name);

                struct ipv6_mreq group;
                memset(&group, 0, sizeof(struct ipv6_mreq));
                inet_pton(AF_INET6, "ff02::fb", &group.ipv6mr_multiaddr);
                group.ipv6mr_interface = index;
                int status = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&group, sizeof(struct ipv6_mreq));
                if (status < 0) {
                    if (errno == EADDRINUSE) {
                        // some interface indexes occurs more than
                        // once, the interface can only be joined for
                        // a multicast group once for each socket.
                    } else {
                        NABTO_LOG_TRACE(LOG, "Cannot add ipv6 membership %d interface name %s", errno, iterator->ifa_name);
                    }
                }
            }
            iterator = iterator->ifa_next;
        }
        freeifaddrs(interfaces);
    }
}
