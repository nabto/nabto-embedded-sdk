#ifndef _NM_TCPTUNNEL_COAP_H_
#define _NM_TCPTUNNEL_COAP_H_

struct nm_tcptunnels;
struct nc_coap_server_context;

np_error_code nm_tcptunnel_coap_init(struct nm_tcptunnels* tunnels, struct nc_coap_server_context* server);
void nm_tcptunnel_coap_deinit(struct nm_tcptunnels* tunnels);

#endif
