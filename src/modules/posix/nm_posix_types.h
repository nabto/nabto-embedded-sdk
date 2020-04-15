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

#endif
