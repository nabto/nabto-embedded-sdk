#ifndef _NM_TCPTUNNEL_COAP_H_
#define _NM_TCPTUNNEL_COAP_H_

struct nm_tcptunnels;
struct nc_coap_server_context;

void nm_tcptunnel_coap_init(struct nm_tcptunnels* tunnels, struct nc_coap_server_context* server);

#endif
