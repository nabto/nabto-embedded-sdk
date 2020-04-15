#ifndef _NM_LIBEVENT_TYPES_H_
#define _NM_LIBEVENT_TYPES_H_


#include <errno.h>

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#include <ws2ipdef.h>
#endif


#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif


#ifdef HAVE_WINSOCK2_H
typedef int ssize_type;
typedef int socklen_type;
#else
typedef ssize_t ssize_type;
typedef socklen_t socklen_type;
#endif

#ifdef HAVE_WINSOCK2_H
#define ERR_IS_EAGAIN(e) ((e) == WSAEWOULDBLOCK || (e) == EAGAIN)
#define ERR_IS_EXPECTED(e) ((e) == EADDRNOTAVAIL || (e) == ENETUNREACH || (e) == EAFNOSUPPORT)
#define ERR_IS_EADDRINUSE(e) ((e) == EADDRINUSE)

#else
#define ERR_IS_EAGAIN(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#define ERR_IS_EXPECTED(e) ((e) == EADDRNOTAVAIL || (e) == ENETUNREACH || (e) == EAFNOSUPPORT)
#define ERR_IS_EADDRINUSE(e) ((e) == EADDRINUSE)
#endif

#ifdef HAVE_WINSOCK2_H
#define NM_INVALID_SOCKET INVALID_SOCKET
#else
#define NM_INVALID_SOCKET -1
#endif


#endif
