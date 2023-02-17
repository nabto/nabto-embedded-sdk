#ifndef _NM_TCP_TUNNEL_CONNECTION_H_
#define _NM_TCP_TUNNEL_CONNECTION_H_

struct nm_tcp_tunnel_connection* nm_tcp_tunnel_connection_new();
void nm_tcp_tunnel_connection_free(struct nm_tcp_tunnel_connection* connection);

np_error_code nm_tcp_tunnel_connection_init(struct nm_tcp_tunnel_service* service, struct nm_tcp_tunnel_connection* connection, struct nc_stream_context* stream, size_t seq);

void nm_tcp_tunnel_connection_start(struct nm_tcp_tunnel_connection* connection);

void nm_tcp_tunnel_connection_stop_from_manager(struct nm_tcp_tunnel_connection* connection);

#endif
