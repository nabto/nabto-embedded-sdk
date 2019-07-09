#ifndef NC_STREAM_MANAGER_H
#define NC_STREAM_MANAGER_H

#include <platform/np_platform.h>
#include <platform/np_dtls_srv.h>
#include <streaming/nabto_stream_window.h>
#include <core/nc_stream.h>

#ifndef NABTO_MAX_STREAMS
#define NABTO_MAX_STREAMS 10
#endif

//TODO: this should take an error code so callback can be resolved if device is closing
typedef void (*nc_stream_manager_listen_callback)(struct nabto_stream* stream, void* data);

struct nc_client_connection;

struct nc_stream_manager_context {
    struct np_platform* pl;
    nc_stream_manager_listen_callback cb;
    void* cbData;
    np_communication_buffer* rstBuf;
    struct nc_stream_context streams[NABTO_MAX_STREAMS];
    struct nc_client_connection* streamConns[NABTO_MAX_STREAMS];
    struct np_dtls_srv_send_context sendCtx;
};



void nc_stream_manager_init(struct nc_stream_manager_context* ctx, struct np_platform* pl);

void nc_stream_manager_set_listener(struct nc_stream_manager_context* ctx, nc_stream_manager_listen_callback cb, void* data);

void nc_stream_manager_handle_packet(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn,
                                     np_communication_buffer* buffer, uint16_t bufferSize);

void nc_stream_manager_close_stream(struct nc_stream_manager_context* ctx, struct nc_stream_context* stream);

void nc_stream_manager_ready_for_accept(struct nc_stream_manager_context* ctx, struct nc_stream_context* stream);

struct nabto_stream_send_segment* nc_stream_manager_alloc_send_segment(struct nc_stream_manager_context* ctx, size_t bufferSize);

void nc_stream_manager_free_send_segment(struct nc_stream_manager_context* ctx, struct nabto_stream_send_segment* segment);

struct nabto_stream_recv_segment* nc_stream_manager_alloc_recv_segment(struct nc_stream_manager_context* ctx, size_t bufferSize);

void nc_stream_manager_free_recv_segment(struct nc_stream_manager_context* ctx, struct nabto_stream_recv_segment* segment);

void nc_stream_manager_remove_connection(struct nc_stream_manager_context* ctx, struct nc_client_connection* connection);

uint64_t nc_stream_manager_get_connection_id(struct nc_stream_manager_context* ctx, struct nabto_stream* stream);

#endif
