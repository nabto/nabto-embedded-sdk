#ifndef _NM_MDNS_H_
#define _NM_MDNS_H_

#include <platform/np_mdns.h>
#include <platform/np_platform.h>
#include <mdns/mdns_server.h>

void nm_mdns_init(struct np_platform* pl);

void nm_mdns_create(struct np_mdns_context** mdns, struct np_platform* pl, const char* productId, const char* deviceId, np_mdns_get_port getPort, void* userData);

void nm_mdns_stop(struct np_mdns_context* mdns);

#endif
