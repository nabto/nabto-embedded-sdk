#ifndef NC_CLIENT_CONNECT_H
#define NC_CLIENT_CONNECT_H

#include <platform/np_platform.h>
#include <platform/np_client_connect.h>

np_error_code nc_client_connect_init(struct np_platform* pl);

np_error_code nc_client_connect_async_create(struct np_platform* pl, struct np_connection_id* id,
                                             struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                             np_client_connect_created_callback cb, void* data);

np_connection* nc_client_connect_get_connection(struct np_platform* pl, struct np_connection_id* id);

np_error_code nc_client_connect_recv(struct np_platform* pl, const np_error_code ec, struct np_udp_socket* sock, struct np_udp_endpoint ep,
                                     np_communication_buffer* buffer, uint16_t bufferSize);

np_error_code nc_client_connect_async_recv_from(np_connection* conn,
                                                np_udp_packet_received_callback cb, void* data);

// TODO: make this:
// np_error_code nc_client_connect_cancel_recv_from(np_connection* conn);
#endif //_NC_CLIENT_CONNECT_H_
