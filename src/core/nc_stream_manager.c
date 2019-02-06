
#include "nc_stream_manager.h"

#include <core/nc_packet.h>
#include <core/nc_client_connect.h>

#include <platform/np_logging.h>

#include <streaming/nabto_stream_log_helper.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_STREAM_MANAGER

//struct nc_stream_manager_context ctx;

struct nc_stream_context* nc_stream_manager_find_stream(struct nc_stream_manager_context* ctx, uint64_t streamId, struct nc_client_connection* conn);
struct nc_stream_context* nc_stream_manager_accept_stream(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn, uint64_t streamId);
void nc_stream_manager_send_rst(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn, uint64_t streamId);
void nc_stream_manager_send_rst_callback(const np_error_code ec, void* data);

void nc_stream_manager_init(struct nc_stream_manager_context* ctx, struct np_platform* pl)
{
    ctx->pl = pl;
}

void nc_stream_manager_set_listener(struct nc_stream_manager_context* ctx, nc_stream_manager_listen_callback cb, void* data)
{
    ctx->cbData = data;
    ctx->cb = cb;
}

void nc_stream_manager_handle_packet(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn,
                                     np_communication_buffer* buffer, uint16_t bufferSize)
{
    uint8_t* start = ctx->pl->buf.start(buffer);
    uint8_t* ptr = start+1; // skip application type
    uint64_t streamId = 0;
    uint8_t streamIdLen = 0;
    uint8_t flags = 0;
    struct nc_stream_context* stream;
    
    NABTO_LOG_INFO(LOG, "stream manager handling packet. AT: %u", *start);
    NABTO_LOG_BUF(LOG, start, bufferSize);
    if (bufferSize < 4) {
        return;
    }
    if(!var_uint_read(ptr, bufferSize-1, &streamId, &streamIdLen)) {
        return;
    }
    NABTO_LOG_INFO(LOG, "streamId=%u", streamId);
    
    ptr += streamIdLen; // skip stream ID
    flags = *ptr;

    stream = nc_stream_manager_find_stream(ctx, streamId, conn);
    
    if (stream == NULL && flags == NABTO_STREAM_FLAG_SYN) {
        stream = nc_stream_manager_accept_stream(ctx, conn, streamId);
    }

    if (stream == NULL && ((flags & NABTO_STREAM_FLAG_RST) != 0)) {
        // only send rst if it's not an rst packet
        nc_stream_manager_send_rst(ctx, conn, streamId);
        return;
    }

    if ( stream != NULL ) {
        nc_stream_handle_packet(stream, ptr, bufferSize-(ptr-start));
    } else {
        NABTO_LOG_TRACE(LOG, "unable to handle packet of type %s, for stream ID %u no such stream", nabto_stream_flags_to_string(flags), streamId);
    }

}

void nc_stream_manager_ready_for_accept(struct nc_stream_manager_context* ctx, struct nc_stream_context* stream)
{
    NABTO_LOG_INFO(LOG, "ready_for_accept cb: %u, stream: %u, cbData: %u", ctx->cb, stream->stream, ctx->cbData);
    if (ctx->cb != NULL) {
        ctx->cb(&stream->stream, ctx->cbData);
    }
    NABTO_LOG_INFO(LOG, "ready_for_accept cb: %u, stream: %u, cbData: %u", ctx->cb, stream->stream, ctx->cbData);
    return;
}

void nc_stream_manager_close_stream(struct nc_stream_manager_context* ctx, struct nc_stream_context* stream)
{
    int i = 0;
    for (i = 0; i < NABTO_MAX_STREAMS; i++) {
        if (&ctx->streams[i] == stream) {
            //memset(&ctx->streams[i], 0, sizeof(struct nc_stream_context));
            ctx->streams[i].streamId = 0;
            ctx->streamConns[i] = NULL;
            return;
        }
    }
}

struct nc_stream_context* nc_stream_manager_find_stream(struct nc_stream_manager_context* ctx, uint64_t streamId, struct nc_client_connection* conn)
{
    int i = 0;
    for (i = 0; i < NABTO_MAX_STREAMS; i++) {
        if (ctx->streams[i].streamId == streamId && ctx->streamConns[i] == conn) {
            return &ctx->streams[i];
        }
    }
    return NULL;
}

struct nc_stream_context* nc_stream_manager_accept_stream(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn, uint64_t streamId)
{
    if ( (streamId % 2) == 1) {
        return NULL;
    } else {
        int i;
        for (i = 0; i < NABTO_MAX_STREAMS; i++) {
            if (ctx->streams[i].active == false) {
                nc_stream_init(ctx->pl, &ctx->streams[i], streamId, nc_client_connect_get_dtls_connection(conn), ctx);
                ctx->streamConns[i] = conn;
                return &ctx->streams[i];
            }
        }
    }
    return NULL;
}

void nc_stream_manager_send_rst(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn, uint64_t streamId)
{
    uint8_t* start;
    uint8_t* ptr;
    size_t ret;
    struct np_dtls_srv_connection* dtls = nc_client_connect_get_dtls_connection(conn);
    NABTO_LOG_TRACE(LOG, "Sending RST to streamId: %u", streamId);
    ctx->rstBuf = ctx->pl->buf.allocate();
    start = ctx->pl->buf.start(ctx->rstBuf);
    ptr = start;
    *ptr = AT_STREAM;
    ptr++;

    ptr = var_uint_write_forward(ptr, streamId);

    ret = nabto_stream_create_rst_packet(ptr, ctx->pl->buf.size(ctx->rstBuf) - (ptr - start));

    ctx->sendCtx.buffer = start;
    ctx->sendCtx.bufferSize = ptr-start+ret;
    ctx->sendCtx.cb = &nc_stream_manager_send_rst_callback;
    ctx->sendCtx.data = ctx;
    ctx->pl->dtlsS.async_send_to(ctx->pl, dtls, &ctx->sendCtx);
}

void nc_stream_manager_send_rst_callback(const np_error_code ec, void* data)
{
    struct nc_stream_manager_context* ctx = (struct nc_stream_manager_context*)data;
    ctx->pl->buf.free(ctx->rstBuf);
}

struct nabto_stream_send_segment* nc_stream_manager_alloc_send_segment(struct nc_stream_manager_context* ctx, size_t bufferSize)
{
    struct nabto_stream_send_segment* seg = (struct nabto_stream_send_segment*)malloc(sizeof(struct nabto_stream_send_segment));
    if (seg == NULL) {
        return NULL;
    }
    memset(seg, 0, sizeof(struct nabto_stream_send_segment));
    uint8_t* buf = (uint8_t*)malloc(bufferSize);
    if (buf == NULL) {
        free(seg);
        return NULL;
    }
    seg->buf = buf;
    seg->capacity = bufferSize;
    return seg;
}

void nc_stream_manager_free_send_segment(struct nc_stream_manager_context* ctx, struct nabto_stream_send_segment* segment)
{
    free(segment->buf);
    free(segment);
}

struct nabto_stream_recv_segment* nc_stream_manager_alloc_recv_segment(struct nc_stream_manager_context* ctx, size_t bufferSize)
{
    struct nabto_stream_recv_segment* seg = (struct nabto_stream_recv_segment*)malloc(sizeof(struct nabto_stream_recv_segment));
    if (seg == NULL) {
        return NULL;
    }
    memset(seg, 0, sizeof(struct nabto_stream_recv_segment));
    uint8_t* buf = (uint8_t*)malloc(bufferSize);
    if (buf == NULL) {
        free(seg);
        return NULL;
    }
    seg->buf = buf;
    seg->capacity = bufferSize;
    return seg;
}

void nc_stream_manager_free_recv_segment(struct nc_stream_manager_context* ctx, struct nabto_stream_recv_segment* segment)
{
    free(segment->buf);
    free(segment);
}
