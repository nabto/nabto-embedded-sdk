#ifndef NC_CLIENT_CONNECT_DISPATCH_H
#define NC_CLIENT_CONNECT_DISPATCH_H

#include <core/nc_client_connect.h>

#ifndef NABTO_MAX_CLIENT_CONNECTIONS
#define NABTO_MAX_CLIENT_CONNECTIONS 10
#endif

void nc_client_connect_dispatch_init(struct np_platform* pl, struct nc_stream_manager_context* streamManager);

void nc_client_connect_dispatch_handle_packet(struct np_platform* pl, const np_error_code ec,
                                              struct np_udp_socket* sock, struct np_udp_endpoint ep,
                                              np_communication_buffer* buffer, uint16_t bufferSize);
np_error_code nc_client_connect_dispatch_close_connection(struct np_platform* pl,
                                                          struct nc_client_connection* conn);

#endif
