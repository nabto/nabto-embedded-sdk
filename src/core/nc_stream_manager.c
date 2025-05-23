
#include "nc_stream_manager.h"

#include <core/nc_client_connection.h>
#include <core/nc_connection.h>
#include <core/nc_packet.h>
#include <core/nc_virtual_stream.h>

#include <platform/np_allocator.h>
#include <platform/np_logging.h>

#include <nabto_stream/nabto_stream_log_helper.h>

#define LOG NABTO_LOG_MODULE_STREAM_MANAGER

//struct nc_stream_manager_context ctx;

struct nc_stream_context* nc_stream_manager_find_stream(struct nc_stream_manager_context* ctx, uint64_t streamId, struct nc_connection* conn);
struct nc_stream_context* nc_stream_manager_accept_stream(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn, uint64_t streamId);

static void nc_stream_manager_send_rst_client_connection(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn, uint64_t streamId);
static void nc_stream_manager_send_rst_callback(const np_error_code ec, void* data);

static uint64_t nc_stream_manager_get_next_nonce(struct nc_stream_manager_context* ctx);

void nc_stream_manager_init(struct nc_stream_manager_context* ctx, struct np_platform* pl, struct nn_log* logger)
{
    ctx->pl = pl;
    ctx->logger = logger;
    ctx->maxSegments = 1000000;
    ctx->maxStreams = SIZE_MAX;
    ctx->nonceCounter = 0;
    nn_llist_init(&ctx->listeners);
    nn_llist_init(&ctx->streams);
    np_completion_event_init(&pl->eq, &ctx->sendRstCtx.ev, &nc_stream_manager_send_rst_callback, ctx);
}

void nc_stream_manager_resolve_listener(struct nc_stream_listener* listener, struct nc_stream_context* stream, np_error_code ec)
{
    listener->cb(ec, stream, listener->cbData);
}

void nc_stream_manager_deinit(struct nc_stream_manager_context* ctx)
{
    if (ctx->pl != NULL) { // if init was called
        struct nc_stream_listener* listener = NULL;
        NN_LLIST_FOREACH(listener, &ctx->listeners)
        {
            nc_stream_manager_resolve_listener(listener, NULL, NABTO_EC_ABORTED);
        }
        np_completion_event_deinit(&ctx->sendRstCtx.ev);
    }
}

bool nc_stream_manager_port_in_use(struct nc_stream_manager_context* ctx, uint32_t type)
{
    struct nc_stream_listener* listener = NULL;
    NN_LLIST_FOREACH(listener, &ctx->listeners)
    {
        if (listener->type == type) {
            return true;
        }
    }
    return false;
}

np_error_code nc_stream_manager_add_listener(struct nc_stream_manager_context* ctx, struct nc_stream_listener* listener, uint32_t type, nc_stream_manager_listen_callback cb, void* data)
{
    if (type == 0) {
        // get ephemeral port number
        np_error_code ec = nc_stream_manager_get_ephemeral_stream_port(ctx, &type);
        if (ec) {
            return ec;
        }
    }

    if (nc_stream_manager_port_in_use(ctx, type)) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }

    listener->cb = cb;
    listener->cbData = data;
    listener->type = type;
    nn_llist_append(&ctx->listeners, &listener->listenersNode, listener);
    return NABTO_EC_OK;
}

void nc_stream_manager_remove_listener(struct nc_stream_listener* listener)
{
    nn_llist_erase_node(&listener->listenersNode);
}

void nc_stream_manager_handle_packet(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn,
                                     uint8_t* buffer, uint16_t bufferSize)
{
    uint8_t* start = buffer;
    uint8_t* ptr = start+1; // skip application type
    uint64_t streamId = 0;
    uint8_t streamIdLen = 0;
    uint8_t flags = 0;
    struct nc_stream_context* stream = NULL;

    NABTO_LOG_TRACE(LOG, "stream manager handling packet. AT: %u", *start);

    if (bufferSize < 4) {
        return;
    }
    if(!var_uint_read(ptr, bufferSize-1, &streamId, &streamIdLen)) {
        return;
    }

    ptr += streamIdLen; // skip stream ID
    flags = *ptr;

    stream = nc_stream_manager_find_stream(ctx, streamId, conn->parent);

    if (stream == NULL && flags == NABTO_STREAM_FLAG_SYN) {
        stream = nc_stream_manager_accept_stream(ctx, conn, streamId);
        if (stream == NULL) {
            NABTO_LOG_ERROR(LOG, "out of streaming resources, sending RST");
        }
    }

    if (stream == NULL && ((flags & NABTO_STREAM_FLAG_RST) != NABTO_STREAM_FLAG_RST)) {
        // only send rst if it's not an rst packet
        nc_stream_manager_send_rst_client_connection(ctx, conn, streamId);
        return;
    }

    if ( stream != NULL ) {
        nc_stream_ref_count_inc(stream);
        nc_stream_handle_packet(stream, ptr, (uint16_t)(bufferSize-(ptr-start)));
        nc_stream_ref_count_dec(stream);
    } else {
        NABTO_LOG_TRACE(LOG, "unable to handle packet of type %s, for stream ID %u no such stream", nabto_stream_flags_to_string(flags), streamId);
    }

}

void nc_stream_manager_ready_for_accept(struct nc_stream_manager_context* ctx, struct nc_stream_context* stream)
{
    // Ownership of the stream has been given to the
    // application. nc_stream_destroy frees the owner ship
    // again.
    nc_stream_ref_count_inc(stream);
    stream->accepted = true; // now it's the responsibility for the
                             // application or this function to call
                             // nc_stream_destroy

    uint32_t type = 0;
    if (stream->isVirtual) {
        type = stream->virt.port;
    } else {
        type = nabto_stream_get_content_type(&stream->stream);
    }
    NABTO_LOG_INFO(LOG, "New stream ready for accept. Looking for listener");
    struct nc_stream_listener* listener = NULL;
    NN_LLIST_FOREACH(listener, &ctx->listeners) {
        if (listener->type == type) {
            nc_stream_manager_resolve_listener(listener, stream, NABTO_EC_OK);
            return;
        }
    }
    // no listener found free the stream and send an rst
    nc_stream_destroy(stream);
    return;
}

struct nc_stream_context* nc_stream_manager_find_stream(struct nc_stream_manager_context* ctx, uint64_t streamId, struct nc_connection* conn)
{
    struct nc_stream_context* stream = NULL;
    NN_LLIST_FOREACH(stream, &ctx->streams) {
        if (stream->streamId == streamId && stream->conn == conn) {
            return stream;
        }
    }
    return NULL;
}

struct nc_stream_context* nc_stream_manager_alloc_stream(struct nc_stream_manager_context* ctx)
{
    if (ctx->currentStreams >= ctx->maxStreams) {
        return NULL;
    }
    struct nc_stream_context* stream = (struct nc_stream_context*)np_calloc(1, sizeof(struct nc_stream_context));

    if (stream == NULL) {
        return NULL;
    }
    stream->streamManager = ctx;
    ctx->currentStreams++;

    return stream;
}

void nc_stream_manager_free_stream(struct nc_stream_context* stream)
{
    struct nc_stream_manager_context* ctx = stream->streamManager;
    ctx->currentStreams--;
    np_free(stream);
}

void nc_stream_manager_stream_remove(struct nc_stream_context* stream)
{
    //struct nc_stream_manager_context* manager = stream->streamManager;
    // remove the stream from the list of streams.
    nn_llist_erase_node(&stream->streamsNode);
    nc_stream_ref_count_dec(stream);
}

struct nc_stream_context* nc_stream_manager_accept_stream(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn, uint64_t streamId)
{
    if ( (streamId % 2) == 1) {
        return NULL;
    }
    struct nc_stream_context* stream = nc_stream_manager_alloc_stream(ctx);
    if (stream == NULL) {
        return NULL;
    }

    uint64_t nonce = nc_stream_manager_get_next_nonce(ctx);

    np_error_code ec = nc_stream_init(ctx->pl, stream, streamId, nonce, conn->parent, ctx, conn->parent->connectionRef, ctx->logger);
    if (ec != NABTO_EC_OK) {
        nc_stream_manager_free_stream(stream);
        return NULL;
    }
    nn_llist_append(&ctx->streams, &stream->streamsNode, stream);
    nc_stream_ref_count_inc(stream);
    return stream;
}

struct nc_stream_context* nc_stream_manager_accept_virtual_stream(struct nc_stream_manager_context* streamManager, struct nc_connection* connection, uint32_t port, struct np_completion_event* openedEv)
{
    struct nc_stream_context* stream = nc_stream_manager_alloc_stream(streamManager);
    if (stream == NULL) {
        return NULL;
    }
    nn_llist_append(&streamManager->streams, &stream->streamsNode, stream);
    np_error_code ec = nc_virtual_stream_init(streamManager->pl, stream, connection, streamManager, port, openedEv);
    nc_stream_ref_count_inc(stream);
    if (ec != NABTO_EC_OK) {
        nc_stream_manager_free_stream(stream);
        return NULL;
    }
    return stream;
}


void nc_stream_manager_send_rst_client_connection(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn, uint64_t streamId)
{
    nc_stream_manager_send_rst(ctx, conn, streamId);
}

void nc_stream_manager_send_rst(struct nc_stream_manager_context* ctx, struct nc_client_connection* conn, uint64_t streamId)
{
    uint8_t* start = NULL;
    uint8_t* ptr = NULL;
    size_t ret = 0;
    NABTO_LOG_TRACE(LOG, "Sending RST to streamId: %u", streamId);
    if (ctx->rstBuf != NULL) {
        NABTO_LOG_INFO(LOG, "RST is sending dropping to send a new rst");
        return;
    }
    ctx->rstBuf = ctx->pl->buf.allocate();
    if (!ctx->rstBuf) {
        NABTO_LOG_ERROR(LOG, "Tried to send RST, but no memory left for packet");
        return;
    }
    start = ctx->pl->buf.start(ctx->rstBuf);
    ptr = start;
    *ptr = AT_STREAM;
    ptr++;

    ptr = var_uint_write_forward(ptr, streamId);

    ret = nabto_stream_create_rst_packet(ptr, ctx->pl->buf.size(ctx->rstBuf) - (ptr - start));

    ctx->sendRstCtx.buffer = start;
    ctx->sendRstCtx.bufferSize = (uint16_t)(ptr-start+ret);
    ctx->sendRstCtx.channelId = NP_DTLS_CLI_DEFAULT_CHANNEL_ID;
    nc_client_connection_async_send_data(conn, &ctx->sendRstCtx);
}

void nc_stream_manager_send_rst_callback(const np_error_code ec, void* data)
{
    (void)ec;
    struct nc_stream_manager_context* ctx = (struct nc_stream_manager_context*)data;
    ctx->pl->buf.free(ctx->rstBuf);
    ctx->rstBuf = NULL;
}

struct nabto_stream_send_segment* nc_stream_manager_alloc_send_segment(struct nc_stream_manager_context* ctx, size_t bufferSize)
{
    if (ctx->allocatedSegments >= ctx->maxSegments) {
        return NULL;
    }

    struct nabto_stream_send_segment* seg = np_calloc(1, sizeof(struct nabto_stream_send_segment));
    if (seg == NULL) {
        return NULL;
    }
    uint8_t* buf = (uint8_t*)np_calloc(1, bufferSize);
    if (buf == NULL) {
        np_free(seg);
        return NULL;
    }
    seg->buf = buf;
    seg->capacity = (uint16_t)bufferSize;
    ctx->allocatedSegments++;
    return seg;
}

void nc_stream_manager_free_send_segment(struct nc_stream_manager_context* ctx, struct nabto_stream_send_segment* segment)
{
    if (segment == NULL) {
        return;
    }
    ctx->allocatedSegments--;
    np_free(segment->buf);
    np_free(segment);
}

struct nabto_stream_recv_segment* nc_stream_manager_alloc_recv_segment(struct nc_stream_manager_context* ctx, size_t bufferSize)
{
    if (ctx->allocatedSegments >= ctx->maxSegments) {
        return NULL;
    }

    struct nabto_stream_recv_segment* seg = np_calloc(1, sizeof(struct nabto_stream_recv_segment));
    if (seg == NULL) {
        return NULL;
    }
    uint8_t* buf = (uint8_t*)np_calloc(1, bufferSize);
    if (buf == NULL) {
        np_free(seg);
        return NULL;
    }
    seg->buf = buf;
    seg->capacity = (uint16_t)bufferSize;
    ctx->allocatedSegments++;
    return seg;
}

void nc_stream_manager_free_recv_segment(struct nc_stream_manager_context* ctx, struct nabto_stream_recv_segment* segment)
{
    if (segment == NULL) {
        return;
    }
    ctx->allocatedSegments--;
    np_free(segment->buf);
    np_free(segment);
}

void nc_stream_manager_remove_connection(struct nc_stream_manager_context* ctx, struct nc_connection* connection)
{
    struct nc_stream_context* stream = NULL;
    struct nn_llist_iterator it = nn_llist_begin(&ctx->streams);
    while (!nn_llist_is_end(&it)) {
        stream = nn_llist_get_item(&it);
        nn_llist_next(&it);

        if (stream->conn == connection) {
            stream->conn = NULL;
            nc_stream_ref_count_inc(stream);
            nc_stream_handle_connection_closed(stream);
            nc_stream_ref_count_dec(stream);
        }
    }
}

uint64_t nc_stream_manager_get_connection_ref(struct nc_stream_manager_context* ctx, struct nabto_stream* nabtoStream)
{
    struct nc_stream_context* stream = NULL;
    NN_LLIST_FOREACH(stream, &ctx->streams) {
        if (&stream->stream == nabtoStream) {
            struct nc_connection* connection = stream->conn;
            if (connection == NULL) {
                return 0;
            }
            return connection->connectionRef;
        }
    }
    return 0;
}

/**
 * An ephemeral stream port is defined as the stream port numbers >= 0x80000000
 */
np_error_code nc_stream_manager_get_ephemeral_stream_port(struct nc_stream_manager_context* ctx, uint32_t* port)
{
    int i = 0;
    for (i = 0; i < 10; i++) {
        uint32_t base = 0x80000000;

        uint32_t r = rand();

        r = r & 0x7FFFFFFF;

        *port = base + r;

        // check that the port is not in use.
        if (!nc_stream_manager_port_in_use(ctx, *port)) {
            return NABTO_EC_OK;
        }
    }
    NABTO_LOG_ERROR(LOG, "Could not allocate an ephemeral stream port.");
    return NABTO_EC_UNKNOWN;
}


void nc_stream_manager_set_max_segments(struct nc_stream_manager_context* ctx, size_t maxSegments)
{
    ctx->maxSegments = maxSegments;
}

uint64_t nc_stream_manager_get_next_nonce(struct nc_stream_manager_context* ctx)
{
    uint64_t nonce = ctx->nonceCounter;
    ctx->nonceCounter++;
    return nonce;
}
