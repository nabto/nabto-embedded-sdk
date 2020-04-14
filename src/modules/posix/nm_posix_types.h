#ifndef _NM_POSIX_TYPES_H_
#define _NM_POSIX_TYPES_H_


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

#if defined(EAGAIN)
#define ERROR_AGAIN EAGAIN
#else
#define ERROR_AGAIN 0
#endif

#if defined(EWOULDBLOCK)
#define ERROR_WOULDBLOCK EWOULDBLOCK
#elif defined(WSAWOULDBLOCK)
#define ERROR_WOULDBLOCK WSAWOULDBLOCK
#endif

#if defined(EADDRNOTAVAIL)
#define ERROR_ADDRNOTAVAIL EADDRNOTAVAIL
#else
#define ERROR_ADDRNOTAVAIL 0
#endif

#if defined(ENETUNREACH)
#define ERROR_NETUNREACH ENETUNREACH
#else
#define ERROR_NETUNREACH 0
#endif

#if defined(EAFNOSUPPORT)
#define ERROR_AFNOSUPPORT EAFNOSUPPORT
#else
#define ERROR_AFNOSUPPORT 0
#endif


#endif
