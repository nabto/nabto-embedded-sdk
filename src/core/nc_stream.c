#include "nc_stream.h"
#include <core/nc_stream_manager.h>
#include <core/nc_packet.h>

#include <platform/np_logging.h>
#include <platform/np_event_queue.h>

#define LOG NABTO_LOG_MODULE_STREAM

struct nabto_stream_module nc_stream_module;


void event(struct nc_stream_context* ctx);
void nc_stream_send_packet(struct nc_stream_context* ctx, enum nabto_stream_next_event_type eventType);
void nc_stream_handle_wait(struct nc_stream_context* ctx);
void nc_stream_handle_timeout(const np_error_code ec, void* data);
void nc_stream_event_callback(enum nabto_stream_module_event event, void* data);
struct nabto_stream_send_segment* nc_stream_alloc_send_segment(size_t bufferSize, void* userData);
void nc_stream_free_send_segment(struct nabto_stream_send_segment* segment, void* userData);
struct nabto_stream_recv_segment* nc_stream_alloc_recv_segment(size_t bufferSize, void* userData);
void nc_stream_free_recv_segment(struct nabto_stream_recv_segment* segment, void* userData);


void nc_stream_log(const char* file, int line, enum nabto_stream_log_level level, const char* fmt, va_list args, void* userData)
{
    switch(level) {
        case NABTO_STREAM_LOG_LEVEL_INFO:
            np_log.log(NABTO_LOG_SEVERITY_INFO, LOG, line, file, fmt, args);
            break;
        case NABTO_STREAM_LOG_LEVEL_TRACE:
            np_log.log(NABTO_LOG_SEVERITY_TRACE, LOG, line, file, fmt, args);
            break;
        case NABTO_STREAM_LOG_LEVEL_DEBUG:
            np_log.log(NABTO_LOG_SEVERITY_DEBUG, LOG, line, file, fmt, args);
            break;
        case NABTO_STREAM_LOG_LEVEL_ERROR:
            np_log.log(NABTO_LOG_SEVERITY_ERROR, LOG, line, file, fmt, args);
            break;
        default:
            np_log.log(NABTO_LOG_SEVERITY_ERROR, LOG, line, file, fmt, args);
            break;
    }
}

np_error_code nc_stream_status_to_ec(nabto_stream_status status)
{
    switch(status) {
        case NABTO_STREAM_STATUS_OK: return NABTO_EC_OK;
        case NABTO_STREAM_STATUS_CLOSED: return NABTO_EC_STREAM_CLOSED;
        case NABTO_STREAM_STATUS_EOF: return NABTO_EC_STREAM_EOF;
        case NABTO_STREAM_STATUS_ABORTED: return NABTO_EC_ABORTED;
        default: return NABTO_EC_FAILED;
    }
}

void nc_stream_init(struct np_platform* pl, struct nc_stream_context* ctx, uint64_t streamId, struct np_dtls_srv_connection* dtls, struct nc_stream_manager_context* streamManager)
{
    nc_stream_module.get_stamp = pl->ts.now_ms;
    nc_stream_module.log = &nc_stream_log;
    nc_stream_module.alloc_send_segment = &nc_stream_alloc_send_segment;
    nc_stream_module.free_send_segment = &nc_stream_free_send_segment;
    nc_stream_module.alloc_recv_segment = &nc_stream_alloc_recv_segment;
    nc_stream_module.free_recv_segment = &nc_stream_free_recv_segment;
    nc_stream_module.notify_event = &nc_stream_event_callback;

    ctx->active = true;
    ctx->dtls = dtls;
    ctx->sendBuffer = pl->buf.allocate();
    ctx->streamId = streamId;
    ctx->streamManager = streamManager;
    ctx->pl = pl;
    ctx->currentExpiry = nabto_stream_stamp_infinite();
    
    nabto_stream_init(&ctx->stream, &nc_stream_module, ctx);
}

void nc_stream_destroy(struct nc_stream_context* ctx)
{
    ctx->active = false;
    ctx->dtls = NULL;
    ctx->pl->buf.free(ctx->sendBuffer);
    ctx->streamId = 0;
    np_event_queue_cancel_timed_event(ctx->pl, &ctx->timer);
}

void nc_stream_event(struct nc_stream_context* ctx)
{
    nabto_stream_send_segment_available(&ctx->stream);
    nabto_stream_recv_segment_available(&ctx->stream);
    enum nabto_stream_next_event_type eventType = nabto_stream_next_event_to_handle(&ctx->stream);

    NABTO_LOG_TRACE(LOG, "next event to handle %s current state %s", nabto_stream_next_event_type_to_string(eventType), nabto_stream_state_as_string(ctx->stream.state));
    switch(eventType) {
        case ET_ACCEPT:
            nc_stream_manager_ready_for_accept(ctx->streamManager, ctx);
            break;
        case ET_ACK:
        case ET_SYN:
        case ET_SYN_ACK:
        case ET_DATA:
        case ET_RST:
            nc_stream_send_packet(ctx, eventType);
            break;
        case ET_TIMEOUT:
            nabto_stream_handle_timeout(&ctx->stream);
            break;
        case ET_APPLICATION_EVENT:
            nabto_stream_dispatch_event(&ctx->stream);
            break;
        case ET_TIME_WAIT:
            nabto_stream_handle_time_wait(&ctx->stream);
            break;
        case ET_WAIT:
            nc_stream_handle_wait(ctx);
            return;
        case ET_NOTHING:
            return;
        case ET_RELEASED:
            nc_stream_destroy(ctx);
            return;
        case ET_CLOSED:
            np_event_queue_cancel_timed_event(ctx->pl, &ctx->timer);
            return;
    }

    nabto_stream_event_handled(&ctx->stream, eventType);
    
    // se if more events can be processed, until we reach ET_WAIT.
    nc_stream_event(ctx);
}

void nc_stream_handle_wait(struct nc_stream_context* ctx)
{
    nabto_stream_stamp nextStamp = nabto_stream_next_event(&ctx->stream);
    if (nextStamp.type == NABTO_STREAM_STAMP_NOW) {
        NABTO_LOG_ERROR(LOG, "Next event should not be now");
        return;
    } else if ( nextStamp.type == NABTO_STREAM_STAMP_INFINITE) {
        return;
    } else {
        if (nabto_stream_stamp_less(nextStamp, ctx->currentExpiry)) {
            ctx->currentExpiry = nextStamp;
            int32_t diff = nabto_stream_stamp_diff_now(&ctx->stream, nextStamp);
            if (diff < 0) {
                ctx->negativeCount += 1;
                if (ctx->negativeCount > 1000) {
                    NABTO_LOG_ERROR(LOG, "next timeout has been negative %u times, this is a problem.", ctx->negativeCount);
                    // mitigate problem until underlying cause is fixed
                    diff = 100;
                }
            } else {
                ctx->negativeCount = 0;
            }
//            np_event_queue_cancel_timed_event(ctx->pl, &ctx->timer);
            np_event_queue_post_timed_event(ctx->pl, &ctx->timer, diff, &nc_stream_handle_timeout, ctx);
        }
    }
}

void nc_stream_handle_timeout(const np_error_code ec, void* data)
{
    struct nc_stream_context* ctx = (struct nc_stream_context*) data;
    NABTO_LOG_TRACE(LOG, "Handle timeout called");
    ctx->currentExpiry = nabto_stream_stamp_infinite();
    nc_stream_event(ctx);
}

void nc_stream_handle_packet(struct nc_stream_context* ctx, uint8_t* buffer, uint16_t bufferSize)
{
    nabto_stream_handle_packet(&ctx->stream, buffer, bufferSize);
    nc_stream_event(ctx);
}

void nc_stream_dtls_send_callback(const np_error_code ec, void* data)
{
    // TODO: possibly handle errors
}

void nc_stream_send_packet(struct nc_stream_context* ctx, enum nabto_stream_next_event_type eventType)
{
    uint8_t* ptr = ctx->pl->buf.start(ctx->sendBuffer);
    uint8_t* start = ptr;
    
    *ptr = (uint8_t)AT_STREAM;
    ptr++;

    ptr = var_uint_write_forward(ptr, ctx->streamId);

    size_t packetSize = nabto_stream_create_packet(&ctx->stream, ptr, ctx->pl->buf.size(ctx->sendBuffer)+start-ptr, eventType);
    if (packetSize == 0) {
        // no packet to send
        return;
    }
    ctx->pl->dtlsS.async_send_to(ctx->pl, ctx->dtls, ctx->pl->buf.start(ctx->sendBuffer), ptr-start+packetSize, &nc_stream_dtls_send_callback, ctx);
}

void nc_stream_event_queue_callback(void* data)
{
    nc_stream_event((struct nc_stream_context*)data);
}

void nc_stream_event_callback(enum nabto_stream_module_event event, void* data)
{
    struct nc_stream_context* ctx = (struct nc_stream_context*) data;
    NABTO_LOG_TRACE(LOG, "nc_stream_event_callback received");
//    np_event_queue_cancel_event(ctx->pl, &ctx->ev);
    np_event_queue_post(ctx->pl, &ctx->ev, &nc_stream_event_queue_callback, ctx);
}

struct nabto_stream_send_segment* nc_stream_alloc_send_segment(size_t bufferSize, void* data)
{
    struct nc_stream_context* ctx = (struct nc_stream_context*) data;
    return nc_stream_manager_alloc_send_segment(ctx->streamManager, bufferSize);
}

void nc_stream_free_send_segment(struct nabto_stream_send_segment* segment, void* data)
{
    struct nc_stream_context* ctx = (struct nc_stream_context*) data;
    nc_stream_manager_free_send_segment(ctx->streamManager, segment);
}
    
struct nabto_stream_recv_segment* nc_stream_alloc_recv_segment(size_t bufferSize, void* data)
{
    struct nc_stream_context* ctx = (struct nc_stream_context*) data;
    return nc_stream_manager_alloc_recv_segment(ctx->streamManager, bufferSize);
}

void nc_stream_free_recv_segment(struct nabto_stream_recv_segment* segment, void* data)
{
    struct nc_stream_context* ctx = (struct nc_stream_context*) data;
    nc_stream_manager_free_recv_segment(ctx->streamManager, segment);
}
