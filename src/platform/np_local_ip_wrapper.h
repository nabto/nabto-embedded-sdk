#ifndef _NP_LOCAL_IP_WRAPPER_H_
#define _NP_LOCAL_IP_WRAPPER_H_

#include "interfaces/np_local_ip.h"

#ifdef __cplusplus
extern "C" {
#endif

size_t np_local_ip_get_local_ips(struct np_local_ip* obj,  struct np_ip_address *addrs, size_t addrsSize);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
