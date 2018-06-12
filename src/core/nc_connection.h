#ifndef NC_CONNECTION_H
#define NC_CONNECTION_H

#include <platform/np_connection.h>
#include <platform/np_platform.h>
#include <nabto_types.h>


void nc_connection_init(struct np_platform* pl);

void nc_connection_async_create(struct np_platform* pl, np_connection* conn, struct np_connection_channel* channel,
                                struct np_connection_id* id, np_connection_created_callback cb, void* data);

np_error_code nc_connection_add_channel(struct np_platform* pl, np_connection* conn,
                                        struct np_connection_channel* channel);

np_error_code nc_connection_rem_channel(struct np_platform* pl, np_connection* conn, uint8_t channelId);

void nc_connection_async_send_to(struct np_platform* pl, np_connection* conn, uint8_t channelId,
                                 np_communication_buffer* buffer, uint16_t bufferSize,
                                 np_connection_sent_callback cb, void* data);

void nc_connection_async_recv_from(struct np_platform* pl, np_connection* conn,
                                   np_connection_received_callback cb, void* data);

np_error_code nc_connection_cancel_async_recv(struct np_platform* pl, np_connection* conn);

void nc_connection_async_destroy(struct np_platform* pl, np_connection* conn,
                                 np_connection_destroyed_callback cb, void* data);


#endif //NC_CONNECTION_H
