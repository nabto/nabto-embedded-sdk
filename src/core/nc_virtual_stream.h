#ifndef NC_VIRTUAL_STREAM_H
#define NC_VIRTUAL_STREAM_H

#include <platform/np_platform.h>
#include <platform/np_completion_event.h>
#include <core/nc_stream.h>

// Initialize a new virtual stream. Called by virtual API.
np_error_code nc_virtual_stream_init(struct np_platform* pl, struct nc_stream_context* ctx, struct nc_connection* conn, struct nc_stream_manager_context* streamManager, uint32_t port, struct np_completion_event* openedEv);

// Server accepted the stream causing the virtual open future to resolve
// virtual has no async version as callbacks are handled in parent
void nc_virtual_stream_server_accepted(struct nc_stream_context* stream);

// Close the virtual stream and resolve outstanding futures
void nc_virtual_stream_handle_connection_closed(struct nc_stream_context* stream);

np_error_code nc_virtual_stream_client_async_read_all(struct nc_stream_context* stream, void* buffer, size_t bufferLength, size_t* readLength, nc_stream_callback callback, void* userData);
np_error_code nc_virtual_stream_client_async_read_some(struct nc_stream_context* stream, void* buffer, size_t bufferLength, size_t* readLength, nc_stream_callback callback, void* userData);
np_error_code nc_virtual_stream_client_async_write(struct nc_stream_context* stream, const void* buffer, size_t bufferLength, nc_stream_callback callback, void* userData);
np_error_code nc_virtual_stream_client_async_close(struct nc_stream_context* stream, nc_stream_callback callback, void* userData);

void nc_virtual_stream_handle_server_data(struct nc_stream_context* stream, const void* buffer, size_t bufferLength, nc_stream_callback callback, void* userData);
void nc_virtual_stream_server_read(struct nc_stream_context* stream);
/**
 * Release ownership of a streaming resource. The resource is then
 * cleaned up by the stream manager module.
 */
void nc_virtual_stream_client_stop(struct nc_stream_context* stream);
void nc_virtual_stream_destroy(struct nc_stream_context* stream);


#endif // NC_VIRTUAL_STREAM_H
