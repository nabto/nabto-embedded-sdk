#ifndef NM_TCP_TUNNEL_COAP_H_
#define NM_TCP_TUNNEL_COAP_H_

struct nm_tcp_tunnels;
struct nc_coap_server_context;

np_error_code nm_tcp_tunnel_coap_init(struct nm_tcp_tunnels* tunnels, struct nc_coap_server_context* server);
void nm_tcp_tunnel_coap_deinit(struct nm_tcp_tunnels* tunnels);

#endif
