#ifndef _NM_TCPTUNNEL_CONNECTION_H_
#define _NM_TCPTUNNEL_CONNECTION_H_

struct nm_tcptunnel_connection* nm_tcptunnel_connection_new();
void nm_tcptunnel_connection_free(struct nm_tcptunnel_connection* connection);

np_error_code nm_tcptunnel_connection_init(struct nm_tcptunnel_service* service, struct nm_tcptunnel_connection* connection, struct nc_stream_context* stream);

void nm_tcptunnel_connection_start(struct nm_tcptunnel_connection* connection);

void nm_tcptunnel_connection_stop_from_manager(struct nm_tcptunnel_connection* connection);

#endif
