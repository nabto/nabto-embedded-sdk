#ifndef _NC_CONNECTION_H_
#define _NC_CONNECTION_H_

#include <platform/np_platform.h>
#include <platform/np_connection.h>
#include <nabto_types.h>

void nc_connection_init(struct np_platform* pl);
void nc_connection_async_create(struct np_platform* pl, np_connection* conn, struct np_udp_endpoint* ep, np_connection_created_callback cb, void* data);
void nc_connection_async_send_to(struct np_platform* pl, np_connection* conn, uint8_t* buffer, uint16_t bufferSize, np_connection_sent_callback cb, void* data);
void nc_connection_async_recv_from(struct np_platform* pl, np_connection* conn, np_connection_received_callback cb, void* data);
np_error_code nc_connection_cancel_async_recv(struct np_platform* pl, np_connection* conn);
void nc_connection_async_destroy(struct np_platform* pl, np_connection* conn, np_connection_destroyed_callback cb, void* data);


#endif //_NC_CONNECTION_H_
