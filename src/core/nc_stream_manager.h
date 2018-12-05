#ifndef NC_STREAM_MANAGER_H
#define NC_STREAM_MANAGER_H

#include <platform/np_platform.h>
#include <streaming/nabto_stream_window.h>
#include <core/nc_stream.h>

#ifndef NABTO_MAX_STREAMS
#define NABTO_MAX_STREAMS 10
#endif

typedef void (*nc_stream_manager_listen_callback)(struct nabto_stream* stream, void* data);

struct nc_stream_manager_context {
    struct np_platform* pl;
    nc_stream_manager_listen_callback cb;
    void* cbData;
    np_communication_buffer* rstBuf;
    struct nc_stream_context streams[NABTO_MAX_STREAMS];
};

struct nc_client_connection;


void nc_stream_manager_init(struct nc_stream_manager_context* ctx, struct np_platform* pl);

void nc_stream_manager_set_listener(struct nc_stream_manager_context* ctx, nc_stream_manager_listen_callback cb, void* data);

void nc_stream_manager_handle_packet(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn,
                                     np_communication_buffer* buffer, uint16_t bufferSize);

void nc_stream_manager_ready_for_accept(struct nc_stream_manager_context* ctx, struct nc_stream_context* stream);

struct nabto_stream_send_segment* nc_stream_manager_alloc_send_segment(struct nc_stream_manager_context* ctx, size_t bufferSize);

void nc_stream_manager_free_send_segment(struct nc_stream_manager_context* ctx, struct nabto_stream_send_segment* segment);
    
struct nabto_stream_recv_segment* nc_stream_manager_alloc_recv_segment(struct nc_stream_manager_context* ctx, size_t bufferSize);

void nc_stream_manager_free_recv_segment(struct nc_stream_manager_context* ctx, struct nabto_stream_recv_segment* segment);

#endif
