#include "nm_select_unix_udp.h"

#include <platform/np_completion_event.h>
#include <platform/np_logging.h>
#include <platform/np_util.h>

#include <modules/mdns/nm_mdns_udp_bind.h>



#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LOG NABTO_LOG_MODULE_UDP

static void nm_select_unix_async_bind_mdns_ipv4(struct np_udp_socket* sock, struct np_completion_event* completionEvent);
static void nm_select_unix_async_bind_mdns_ipv6(struct np_udp_socket* sock, struct np_completion_event* completionEvent);
static np_error_code create_socket_ipv6(struct np_udp_socket* s);
static np_error_code create_socket_ipv4(struct np_udp_socket* s);
static bool init_mdns_ipv6_socket(int sock);
static bool init_mdns_ipv4_socket(int sock);
static void mdns_update_ipv4_socket_registration(int sock);
static void mdns_update_ipv6_socket_registration(int sock);


static struct nm_mdns_udp_bind_functions module = {
    .async_bind_mdns_ipv4 = &nm_select_unix_async_bind_mdns_ipv4,
    .async_bind_mdns_ipv6 = &nm_select_unix_async_bind_mdns_ipv6
};

struct nm_mdns_udp_bind nm_select_unix_mdns_udp_bind_get_impl(struct nm_select_unix* ctx)
{
    struct nm_mdns_udp_bind obj;
    obj.mptr = &module;
    obj.data = ctx;
    return obj;
}


np_error_code nm_select_unix_async_bind_mdns_ipv4_ec(struct np_udp_socket* sock)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec = create_socket_ipv4(sock);

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


np_error_code create_socket_ipv6(struct np_udp_socket* s)
{
    int sock = nm_select_unix_udp_nonblocking_socket(AF_INET6, SOCK_DGRAM);
    if (sock == NM_SELECT_UNIX_INVALID_SOCKET) {
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
    int sock = nm_select_unix_udp_nonblocking_socket(AF_INET, SOCK_DGRAM);
    if (sock == NM_SELECT_UNIX_INVALID_SOCKET) {
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
                unsigned int index = if_nametoindex(iterator->ifa_name);
                if (index == 0) {
                    NABTO_LOG_ERROR(LOG, "Cannot get index for interface '%s'", iterator->ifa_name);
                } else {
                    // we assume there is not so many interfaces that the index will wrap the int
                    group.imr_ifindex = (int)index;
                    int status = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&group, sizeof(group));
                    if (status < 0) {
                        if (errno == EADDRINUSE) {
                            // ok probable already registered
                        } else {
                            NABTO_LOG_TRACE(LOG, "Cannot add ipv4 membership %d interface %s", errno, iterator->ifa_name);
                        }
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
                // we assume there is not so many interfaces that the index will wrap the int
                int index = (int)if_nametoindex(iterator->ifa_name);
                if (index == 0) {
                    NABTO_LOG_ERROR(LOG, "Cannot get index for interface '%s'", iterator->ifa_name);
                } else {
                    struct ipv6_mreq group;
                    memset(&group, 0, sizeof(struct ipv6_mreq));
                    inet_pton(AF_INET6, "ff02::fb", &group.ipv6mr_multiaddr);
                    group.ipv6mr_interface = index;
                    int status = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char*)&group, sizeof(struct ipv6_mreq));
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
            }
            iterator = iterator->ifa_next;
        }
        freeifaddrs(interfaces);
    }
}
