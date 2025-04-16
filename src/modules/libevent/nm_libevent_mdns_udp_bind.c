#include "nm_libevent_mdns_udp_bind.h"

#include "nm_libevent.h"
#include "nm_libevent_udp.h"

#include <platform/np_error_code.h>
#include <platform/np_ip_address.h>
#include <platform/np_logging.h>

#include "nm_libevent_types.h"
#include <event.h>
#include <event2/event.h>
#include <event2/util.h>

#if defined(HAVE_SYS_SOCKET_H)
#include <sys/socket.h>
#endif

#if defined(HAVE_NETINET_IN_H)
#include <netinet/in.h>
#endif

#if defined(HAVE_IFADDRS_H)
#include <ifaddrs.h>
#endif

#if defined(HAVE_ARPA_INET_H)
#include <arpa/inet.h>
#endif

#if defined(HAVE_NET_IF_H)
#include <net/if.h>
#endif

#if defined(HAVE_WINSOCK2_H)
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#endif

#include <string.h>

#define LOG NABTO_LOG_MODULE_UDP

static void udp_async_bind_mdns_ipv4(struct np_udp_socket* sock, struct np_completion_event* completionEvent);
static void udp_async_bind_mdns_ipv6(struct np_udp_socket* sock, struct np_completion_event* completionEvent);

static np_error_code udp_create_socket_ipv4(struct np_udp_socket* s);
static np_error_code udp_create_socket_ipv6(struct np_udp_socket* s);


static bool nm_libevent_init_mdns_ipv6_socket(evutil_socket_t sock);
static bool nm_libevent_init_mdns_ipv4_socket(evutil_socket_t sock);

static void nm_libevent_mdns_update_ipv4_socket_registration(evutil_socket_t sock);
static void nm_libevent_mdns_update_ipv6_socket_registration(evutil_socket_t sock);

static struct nm_mdns_udp_bind_functions module = {
    .async_bind_mdns_ipv4 = udp_async_bind_mdns_ipv4,
    .async_bind_mdns_ipv6 = udp_async_bind_mdns_ipv6
};

struct nm_mdns_udp_bind nm_libevent_mdns_udp_bind_get_impl(struct nm_libevent_context* libeventContext)
{
    struct nm_mdns_udp_bind obj;
    obj.mptr = &module;
    obj.data = libeventContext;
    return obj;
}
np_error_code udp_async_bind_mdns_ipv4_ec(struct np_udp_socket* sock)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec = udp_create_socket_ipv4(sock);

    if (ec != NABTO_EC_OK) {
        return ec;
    }

    if (!nm_libevent_init_mdns_ipv4_socket(sock->sock)) {
        evutil_closesocket(sock->sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    nm_libevent_mdns_update_ipv4_socket_registration(sock->sock);

    ec = nm_libevent_udp_add_to_libevent(sock);
    if (ec != NABTO_EC_OK) {
        evutil_closesocket(sock->sock);
        return ec;
    }
    return NABTO_EC_OK;
}

void udp_async_bind_mdns_ipv4(struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    np_error_code ec = udp_async_bind_mdns_ipv4_ec(sock);
    np_completion_event_resolve(completionEvent, ec);
}

np_error_code udp_async_bind_mdns_ipv6_ec(struct np_udp_socket* sock)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec = udp_create_socket_ipv6(sock);
    if (ec) {
        return ec;
    }

    if (!nm_libevent_init_mdns_ipv6_socket(sock->sock)) {
        evutil_closesocket(sock->sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    nm_libevent_mdns_update_ipv6_socket_registration(sock->sock);

    ec = nm_libevent_udp_add_to_libevent(sock);
    if (ec != NABTO_EC_OK) {
        evutil_closesocket(sock->sock);
        return ec;
    }
    return NABTO_EC_OK;
}

void udp_async_bind_mdns_ipv6(struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    np_error_code ec = udp_async_bind_mdns_ipv6_ec(sock);
    np_completion_event_resolve(completionEvent, ec);
}


np_error_code udp_create_socket_ipv6(struct np_udp_socket* s)
{
    evutil_socket_t sock = nm_libevent_udp_create_nonblocking_socket(AF_INET6, SOCK_DGRAM);
    if (sock == NM_INVALID_SOCKET) {
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    int yes = 1;
    int status = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &yes, sizeof(yes));
    if (status < 0) {
        NABTO_LOG_ERROR(LOG, "Cannot set IPV6_V6ONLY");
    }

    s->type = NABTO_IPV6;
    s->sock = sock;
    return NABTO_EC_OK;
}

np_error_code udp_create_socket_ipv4(struct np_udp_socket* s)
{
    evutil_socket_t sock = nm_libevent_udp_create_nonblocking_socket(AF_INET, SOCK_DGRAM);
    if (sock == NM_INVALID_SOCKET) {
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }
    s->type = NABTO_IPV4;
    s->sock = sock;
    return NABTO_EC_OK;
}


bool nm_libevent_init_mdns_ipv6_socket(evutil_socket_t sock)
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
        int e = EVUTIL_SOCKET_ERROR();
        NABTO_LOG_INFO(LOG, "bind mdns ipv6 failed (%d) %s", e, evutil_socket_error_to_string(e));
        return false;
    }

    struct ipv6_mreq group;
    memset(&group, 0, sizeof(struct ipv6_mreq));
    inet_pton(AF_INET6, "ff02::fb", &group.ipv6mr_multiaddr);
    group.ipv6mr_interface = 0;
    int status = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&group, sizeof(struct ipv6_mreq));
    if (status < 0) {
        int e = EVUTIL_SOCKET_ERROR();
        if (ERR_IS_EXPECTED(e)) {
            NABTO_LOG_TRACE(LOG, "Cannot add ipv6 default membership (%d) %s", e, evutil_socket_error_to_string(e));
        } else {
            NABTO_LOG_ERROR(LOG, "Cannot add ipv6 default membership (%d) %s", e, evutil_socket_error_to_string(e));
        }
    }

    return true;
}


bool nm_libevent_init_mdns_ipv4_socket(evutil_socket_t sock)
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
        int e = EVUTIL_SOCKET_ERROR();
        NABTO_LOG_ERROR(LOG, "Cannot add ipv4 default membership (%d) %s", e, evutil_socket_error_to_string(e));
    }

    return true;
}


void nm_libevent_mdns_update_ipv4_socket_registration(evutil_socket_t sock)
{
#if defined(HAVE_IFADDRS_H)
    struct ifaddrs* interfaces = NULL;
    if (getifaddrs(&interfaces) == 0) {

        struct ifaddrs* iterator = interfaces;
        while (iterator != NULL) {
            if (iterator->ifa_addr != NULL) {
                struct ip_mreqn group;
                memset(&group, 0, sizeof(struct ip_mreq));
                group.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
                unsigned int index = if_nametoindex(iterator->ifa_name);
                if (index == 0) {
                    NABTO_LOG_ERROR(LOG, "Cannot get index for interface '%s'", iterator->ifa_name);
                } else {
                    group.imr_ifindex = (int)index;
                    int status = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&group, sizeof(group));
                    if (status < 0) {
                        int e = EVUTIL_SOCKET_ERROR();
                        if (ERR_IS_EADDRINUSE(e)) {
                            // ok probable already registered
                        } else {
                            NABTO_LOG_TRACE(LOG, "Cannot add ipv4 membership (%d) %s, interface %s", e, evutil_socket_error_to_string(e), iterator->ifa_name);
                        }
                    }
                }
            }

            iterator = iterator->ifa_next;
        }
        freeifaddrs(interfaces);
    }
#else
    (void)sock;
#endif
}

void nm_libevent_mdns_update_ipv6_socket_registration(evutil_socket_t sock)
{
#if defined(HAVE_IFADDRS_H)
    struct ifaddrs* interfaces = NULL;
    if (getifaddrs(&interfaces) == 0) {

        struct ifaddrs* iterator = interfaces;
        while (iterator != NULL) {
            if (iterator->ifa_addr != NULL)
            {
                unsigned int index = if_nametoindex(iterator->ifa_name);
                if (index == 0) {
                    NABTO_LOG_ERROR(LOG, "Cannot get index for interface '%s'", iterator->ifa_name);
                } else {
                    struct ipv6_mreq group;
                    memset(&group, 0, sizeof(struct ipv6_mreq));
                    inet_pton(AF_INET6, "ff02::fb", &group.ipv6mr_multiaddr);
                    group.ipv6mr_interface = index;
                    int status = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char*)&group, sizeof(struct ipv6_mreq));
                    if (status < 0) {
                        int e = EVUTIL_SOCKET_ERROR();
                        if (ERR_IS_EADDRINUSE(e)) {
                            // some interface indexes occurs more than
                            // once, the interface can only be joined for
                            // a multicast group once for each socket.
                        } else {
                            NABTO_LOG_TRACE(LOG, "Cannot add ipv6 membership (%d) %s,  interface name %s", e, evutil_socket_error_to_string(e), iterator->ifa_name);
                        }
                    }
                }
            }
            iterator = iterator->ifa_next;
        }
        freeifaddrs(interfaces);
    }
#else
    // silence compiler unused warning
    (void)sock;
#endif
}
