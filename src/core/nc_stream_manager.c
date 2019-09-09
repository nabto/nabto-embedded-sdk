
#include "nc_stream_manager.h"

#include <core/nc_packet.h>
#include <core/nc_client_connection.h>

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

    ctx->listenerSentinel.prev = &ctx->listenerSentinel;
    ctx->listenerSentinel.next = &ctx->listenerSentinel;
}

void nc_stream_manager_resolve_listener(struct nc_stream_listener* listener, struct nc_stream_context* stream, np_error_code ec)
{
    // remove listener from list
    struct nc_stream_listener* before = listener->prev;
    struct nc_stream_listener* after = listener->next;

    before->next = after;
    after->prev = before;

    listener->cb(ec, stream, listener->cbData);
}

void nc_stream_manager_deinit(struct nc_stream_manager_context* ctx)
{
    while (ctx->listenerSentinel.next != &ctx->listenerSentinel) {
        struct nc_stream_listener* listener = ctx->listenerSentinel.next;
        nc_stream_manager_resolve_listener(listener, NULL, NABTO_EC_ABORTED);
    }
}

np_error_code nc_stream_manager_add_listener(struct nc_stream_manager_context* ctx, struct nc_stream_listener* listener, uint32_t type, nc_stream_manager_listen_callback cb, void* data)
{
    np_error_code ec;
    if (type == 0) {
        // get ephemeral port number
        ec = nc_stream_manager_get_ephemeral_stream_port(ctx, &type);
        if (ec) {
            return ec;
        }
    }

    listener->cb = cb;
    listener->cbData = data;
    listener->type = type;
    struct nc_stream_listener* before = ctx->listenerSentinel.prev;
    struct nc_stream_listener* after = &ctx->listenerSentinel;

    before->next = listener;
    listener->next = after;
    after->prev = listener;
    listener->prev = before;
    return NABTO_EC_OK;
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

    NABTO_LOG_TRACE(LOG, "stream manager handling packet. AT: %u", *start);

    if (bufferSize < 4) {
        return;
    }
    if(!var_uint_read(ptr, bufferSize-1, &streamId, &streamIdLen)) {
        return;
    }

    ptr += streamIdLen; // skip stream ID
    flags = *ptr;

    stream = nc_stream_manager_find_stream(ctx, streamId, conn);

    if (stream == NULL && flags == NABTO_STREAM_FLAG_SYN) {
        stream = nc_stream_manager_accept_stream(ctx, conn, streamId);
        if (stream == NULL) {
            NABTO_LOG_ERROR(LOG, "out of streaming resources, sending RST");
        }
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
    uint32_t type = nabto_stream_get_content_type(&stream->stream);

    struct nc_stream_listener* iterator = ctx->listenerSentinel.next;
    while (iterator != &ctx->listenerSentinel) {
        if (iterator->type == type) {
            nc_stream_manager_resolve_listener(iterator, stream, NABTO_EC_OK);
            return;
        }
        iterator = iterator->next;
    }
    nabto_stream_release(&stream->stream);
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
                nc_stream_init(ctx->pl, &ctx->streams[i], streamId, nc_client_connection_get_dtls_connection(conn), ctx);
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
    struct np_dtls_srv_connection* dtls = nc_client_connection_get_dtls_connection(conn);
    NABTO_LOG_TRACE(LOG, "Sending RST to streamId: %u", streamId);
    if (ctx->rstBuf != NULL) {
        NABTO_LOG_INFO(LOG, "RST is sending dropping to send a new rst");
        return;
    }
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
    ctx->sendCtx.channelId = NP_DTLS_SRV_DEFAULT_CHANNEL_ID;
    ctx->pl->dtlsS.async_send_data(ctx->pl, dtls, &ctx->sendCtx);
}

void nc_stream_manager_send_rst_callback(const np_error_code ec, void* data)
{
    struct nc_stream_manager_context* ctx = (struct nc_stream_manager_context*)data;
    ctx->pl->buf.free(ctx->rstBuf);
    ctx->rstBuf = NULL;
}

struct nabto_stream_send_segment* nc_stream_manager_alloc_send_segment(struct nc_stream_manager_context* ctx, size_t bufferSize)
{
    struct nabto_stream_send_segment* seg = calloc(1, sizeof(struct nabto_stream_send_segment));
    if (seg == NULL) {
        return NULL;
    }
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
    struct nabto_stream_recv_segment* seg = calloc(1, sizeof(struct nabto_stream_recv_segment));
    if (seg == NULL) {
        return NULL;
    }
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

void nc_stream_manager_remove_connection(struct nc_stream_manager_context* ctx, struct nc_client_connection* connection)
{
    int i;
    for(i = 0; i < NABTO_MAX_STREAMS; i++) {
        if (ctx->streamConns[i] == connection) {
            ctx->streamConns[i] = NULL;
            nc_stream_remove_connection(&ctx->streams[i]);
        }
    }
}

uint64_t nc_stream_manager_get_connection_ref(struct nc_stream_manager_context* ctx, struct nabto_stream* stream)
{
    for (int i = 0; i < NABTO_MAX_STREAMS; i++) {

        if (ctx->streams[i].active && &ctx->streams[i].stream == stream) {
            struct nc_client_connection* connection = ctx->streamConns[i];
            if (connection == NULL) {
                return 0;
            } else {
                return connection->connectionRef;
            }
        }
    }
    return 0;
}

/**
 * An ephemeral stream port is defined as the stream port numbers >= 0x80000000
 */
np_error_code nc_stream_manager_get_ephemeral_stream_port(struct nc_stream_manager_context* ctx, uint32_t* port)
{
    int i;
    for (i = 0; i < 10; i++) {
        uint32_t base = 0x80000000;

        uint32_t r = rand();

        r = r & 0x7FFFFFFF;

        *port = base + r;

        // check that the port is not in use.
        bool found = false;
        struct nc_stream_listener* iterator = ctx->listenerSentinel.next;
        while (iterator != &ctx->listenerSentinel) {
            if (iterator->type == *port) {
                found = true;
            }
            iterator = iterator->next;
        }
        if (!found) {
            return NABTO_EC_OK;
        }
    }
    return NABTO_EC_FAILED;
}
