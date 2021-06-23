#include "nm_libevent_get_local_ip.h"
#include "nm_libevent_types.h"
#include "nm_libevent.h"

#include <platform/np_logging.h>
#include <platform/interfaces/np_local_ip.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_WINDOWS_H
#include <windows.h>
#include <winsock2.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#endif

#include <event2/util.h>

#define LOG NABTO_LOG_MODULE_UDP

static size_t get_local_ips(struct np_local_ip* obj, struct np_ip_address *addrs, size_t addrsSize);


const struct np_local_ip_functions module = {
    .get_local_ips = get_local_ips
};

struct np_local_ip nm_libevent_local_ip_get_impl(struct nm_libevent_context* ctx)
{
    struct np_local_ip obj;
    obj.mptr = &module;
    obj.data = ctx;
    return obj;
}

size_t get_local_ips(struct np_local_ip* obj, struct np_ip_address *addrs, size_t addrsSize)
{
    (void)obj;
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
    evutil_socket_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s != NM_INVALID_SOCKET) {
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
            socklen_type len = sizeof my_addr;
            if(getsockname(s,(struct sockaddr*)&my_addr,&len) == -1) {
                NABTO_LOG_ERROR(LOG, "getsockname failed");
            } else {
                if (memcmp(&my_addr.sin_addr, &v4any, 4) != 0) {
                    addrs[ind].type = NABTO_IPV4;
                    memcpy(addrs[ind].ip.v4, &my_addr.sin_addr.s_addr, 4);
                    ind++;
                }
            }
        }
        evutil_closesocket(s);
    }
    if (addrsSize < ind+1) {
        return ind;
    }
    s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s != NM_INVALID_SOCKET) {
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
            socklen_type len = sizeof my_addr;
            if(getsockname(s,(struct sockaddr*)&my_addr,&len) == -1) {
                NABTO_LOG_ERROR(LOG, "getsockname failed");
            } else {
                if (memcmp(&my_addr.sin6_addr, &v6any, 16) != 0) {
                    addrs[ind].type = NABTO_IPV6;
                    memcpy(addrs[ind].ip.v6, my_addr.sin6_addr.s6_addr, 16);
                    ind++;
                }
            }
        }
        evutil_closesocket(s);
    }
    return ind;
}
