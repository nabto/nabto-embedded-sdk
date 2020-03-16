#ifndef _TCP_TUNNEL_H_
#define _TCP_TUNNEL_H_

struct tcp_tunnel {

};

np_error_code tcp_tunnel_init(struct tcp_tunnel* tcpTunnel);
void tcp_tunnel_deinit(struct tcp_tunnel* tcpTunnel);

#endif
