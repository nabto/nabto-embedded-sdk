#include "nm_posix_mdns.h"
#include "nm_posix_types.h"

#include <platform/np_logging.h>

#if defined(HAVE_SYS_SOCKET_H)
#include <sys/socket.h>
#endif

#if defined(HAVE_NETINET_IN_H)
#include <netinet/in.h>
#endif

#include <string.h>

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

#include <errno.h>

#define LOG NABTO_LOG_MODULE_UDP

bool nm_posix_init_mdns_ipv6_socket(int sock)
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
        int e = errno;
        NABTO_LOG_INFO(LOG, "bind mdns ipv6 failed (%d) %s", e, strerror(e));
        return false;
    }

    struct ipv6_mreq group;
    memset(&group, 0, sizeof(struct ipv6_mreq));
    inet_pton(AF_INET6, "ff02::fb", &group.ipv6mr_multiaddr);
    group.ipv6mr_interface = 0;
    int status = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&group, sizeof(struct ipv6_mreq));
    if (status < 0) {
        int e = errno;
        NABTO_LOG_ERROR(LOG, "Cannot add ipv6 default membership (%d) %s", e, strerror(e));
    }

    return true;
}


bool nm_posix_init_mdns_ipv4_socket(int sock)
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
        int e = errno;
        NABTO_LOG_ERROR(LOG, "Cannot add ipv4 default membership (%d) %s", e, strerror(e));
    }

    return true;
}


void nm_posix_mdns_update_ipv4_socket_registration(int sock)
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
                //struct sockaddr_in* in = (struct sockaddr_in*)iterator->ifa_addr;
                int index = if_nametoindex(iterator->ifa_name);
                group.imr_ifindex = index;
                int status = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group));
                if (status < 0) {
                    int e = errno;
                    if (e == EADDRINUSE) {
                        // ok probable already registered
                    } else {
                        NABTO_LOG_TRACE(LOG, "Cannot add ipv4 membership (%d) %s, interface %s", e, strerror(e), iterator->ifa_name);
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

void nm_posix_mdns_update_ipv6_socket_registration(int sock)
{
#if defined(HAVE_IFADDRS_H)
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
                    int e = errno;
                    if (e == EADDRINUSE) {
                        // some interface indexes occurs more than
                        // once, the interface can only be joined for
                        // a multicast group once for each socket.
                    } else {
                        NABTO_LOG_TRACE(LOG, "Cannot add ipv6 membership (%d) %s,  interface name %s", e, strerror(e), iterator->ifa_name);
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
