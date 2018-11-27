
#include "nc_stream_manager.h"
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_STREAM_MANAGER

void nc_stream_manager_handle_packet(struct nc_client_connection* conn,
                                     np_communication_buffer* buffer, uint16_t bufferSize)
{
    NABTO_LOG_TRACE(LOG, "stream manager handling packet");
}
