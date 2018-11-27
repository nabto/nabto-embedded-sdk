#ifndef NC_STREAM_MANAGER_H
#define NC_STREAM_MANAGER_H

#include <platform/np_platform.h>

void nc_stream_manager_handle_packet(struct nc_client_connection* conn,
                                     np_communication_buffer* buffer, uint16_t bufferSize);

#endif
