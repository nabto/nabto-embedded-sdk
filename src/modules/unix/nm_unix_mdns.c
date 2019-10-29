#include "nm_unix_mdns.h"

#include <platform/np_logging.h>

#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>

#define LOG NABTO_LOG_MODULE_UDP


bool nm_unix_init_mdns_ipv6_socket(int sock)
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

    {
        struct ifaddrs* interfaces = NULL;
        bool foundIf = false;
        if (getifaddrs(&interfaces) == 0) {

            struct ifaddrs* iterator = interfaces;
            while (iterator != NULL) {
                if (iterator->ifa_addr != NULL &&
                    iterator->ifa_addr->sa_family == AF_INET6)
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
                            NABTO_LOG_ERROR(LOG, "Cannot add ipv6 membership %d interface name %s %d", errno, iterator->ifa_name, iterator->ifa_addr->sa_family);
                        }
                    }
                } else {
                    NABTO_LOG_TRACE(LOG, "Found suitable mDNS interface: %s", iterator->ifa_name);
                    foundIf = true;
                }
                iterator = iterator->ifa_next;
            }
            freeifaddrs(interfaces);
        }
        return foundIf;
    }
}


bool nm_unix_init_mdns_ipv4_socket(int sock)
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
                if (iterator->ifa_addr != NULL && iterator->ifa_addr->sa_family == AF_INET) {
                    struct ip_mreq group;
                    memset(&group, 0, sizeof(struct ip_mreq));
                    group.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
                    struct sockaddr_in* in = (struct sockaddr_in*)iterator->ifa_addr;
                    group.imr_interface = in->sin_addr;
                    int status = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group));
                    if (status < 0) {
                        NABTO_LOG_ERROR(LOG, "Cannot add ipv4 membership %d", errno);
                    }

                }

                iterator = iterator->ifa_next;
            }
            freeifaddrs(interfaces);
        }
    }
    return true;
}
