#include "nc_stream.h"
#include <core/nc_stream_manager.h>
#include <core/nc_packet.h>

#include <platform/np_logging.h>
#include <platform/interfaces/np_event_queue.h>
#include <platform/np_timestamp_wrapper.h>
#include <platform/np_event_queue_wrapper.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_STREAM

struct nabto_stream_module nc_stream_module;

static void nc_stream_application_event_callback(nabto_stream_application_event_type eventType, void* data);

static void nc_stream_event_queue_callback(void* data);
static void nc_stream_free(struct nc_stream_context* stream);

void event(struct nc_stream_context* ctx);
void nc_stream_send_packet(struct nc_stream_context* ctx, enum nabto_stream_next_event_type eventType);
void nc_stream_handle_wait(struct nc_stream_context* ctx);
void nc_stream_handle_timeout(void* data);
void nc_stream_event_callback(enum nabto_stream_module_event event, void* data);
struct nabto_stream_send_segment* nc_stream_alloc_send_segment(size_t bufferSize, void* userData);
void nc_stream_free_send_segment(struct nabto_stream_send_segment* segment, void* userData);
struct nabto_stream_recv_segment* nc_stream_alloc_recv_segment(size_t bufferSize, void* userData);
void nc_stream_free_recv_segment(struct nabto_stream_recv_segment* segment, void* userData);

np_error_code nc_stream_status_to_ec(nabto_stream_status status)
{
    switch(status) {
        case NABTO_STREAM_STATUS_OK: return NABTO_EC_OK;
        case NABTO_STREAM_STATUS_CLOSED: return NABTO_EC_CLOSED;
        case NABTO_STREAM_STATUS_EOF: return NABTO_EC_EOF;
        case NABTO_STREAM_STATUS_ABORTED: return NABTO_EC_ABORTED;
        default: return NABTO_EC_UNKNOWN;
    }
}

uint32_t nc_stream_get_stamp(void* userData)
{
    struct nc_stream_context* ctx = (struct nc_stream_context*)userData;
    return np_timestamp_now_ms(&ctx->pl->timestamp);
}

np_error_code nc_stream_init(struct np_platform* pl, struct nc_stream_context* ctx, uint64_t streamId, uint64_t nonce, struct np_dtls_srv_connection* dtls, struct nc_client_connection* clientConn, struct nc_stream_manager_context* streamManager, uint64_t connectionRef, struct nn_log* logger)
{
    nc_stream_module.get_stamp = &nc_stream_get_stamp;
    nc_stream_module.logger = logger;
    nc_stream_module.alloc_send_segment = &nc_stream_alloc_send_segment;
    nc_stream_module.free_send_segment = &nc_stream_free_send_segment;
    nc_stream_module.alloc_recv_segment = &nc_stream_alloc_recv_segment;
    nc_stream_module.free_recv_segment = &nc_stream_free_recv_segment;
    nc_stream_module.notify_event = &nc_stream_event_callback;

    np_error_code ec;
    ec = np_event_queue_create_event(&pl->eq, &nc_stream_event_queue_callback, ctx, &ctx->ev);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_event_queue_create_event(&pl->eq, &nc_stream_handle_timeout, ctx, &ctx->timer);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ctx->refCount = 0;
    ctx->stopped = false;
    ctx->dtls = dtls;
    ctx->clientConn = clientConn;
    ctx->streamId = streamId;
    ctx->streamManager = streamManager;
    ctx->pl = pl;
    ctx->currentExpiry = nabto_stream_stamp_infinite();
    ctx->isSending = false;
    ctx->connectionRef = connectionRef;
    ctx->accepted = false;


    nabto_stream_init(&ctx->stream, &nc_stream_module, ctx);
    nabto_stream_set_application_event_callback(&ctx->stream, &nc_stream_application_event_callback, ctx);
    uint8_t* noncePtr = (uint8_t*)&nonce;
    nabto_stream_init_responder(&ctx->stream, noncePtr);
    return NABTO_EC_OK;
}

void nc_stream_destroy(struct nc_stream_context* ctx)
{
    // this is called after the stream ownership has been given to an application.
    nc_stream_stop(ctx);
    nc_stream_manager_stream_remove(ctx);
    nc_stream_ref_count_dec(ctx);
}

void nc_stream_free(struct nc_stream_context* ctx)
{
    struct np_event_queue* eq = &ctx->pl->eq;
    np_event_queue_destroy_event(eq, ctx->ev);
    np_event_queue_destroy_event(eq, ctx->timer);

    nc_stream_manager_free_stream(ctx);
}

void nc_stream_event(struct nc_stream_context* ctx)
{
    while (true) {
        if (ctx->stopped) {
            return;
        }
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
                return;
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
            case ET_CLOSED:
                return;
        }

        nabto_stream_event_handled(&ctx->stream, eventType);

        if (ctx->stopped) {
            return;
        }
    }
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
            diff += 2; // make sure that we have passed the timestamp inside the module.
            np_event_queue_post_timed_event(&ctx->pl->eq, ctx->timer, diff);
        }
    }
}

void nc_stream_handle_timeout(void* data)
{
    struct nc_stream_context* ctx = (struct nc_stream_context*) data;
    if (ctx->stopped) {
        return;
    }
    ctx->currentExpiry = nabto_stream_stamp_infinite();
    nc_stream_event(ctx);
}

void nc_stream_handle_packet(struct nc_stream_context* ctx, uint8_t* buffer, uint16_t bufferSize)
{
    if (ctx->stopped) {
        return;
    }
    nabto_stream_handle_packet(&ctx->stream, buffer, bufferSize);
    nc_stream_event(ctx);
}

void nc_stream_handle_connection_closed(struct nc_stream_context* ctx)
{
    if (ctx->stopped) {
        return;
    }
    ctx->dtls = NULL;

    nc_stream_stop(ctx);

    if (!ctx->accepted) {
        // the ownership hasn't been tranferred to an user application. free the stream from here.
        nc_stream_manager_stream_remove(ctx);
    }
}

void nc_stream_dtls_send_callback(const np_error_code ec, void* data)
{
    struct nc_stream_context* ctx = data;
    ctx->isSending = false;
    if (!ctx->stopped) {
        nabto_stream_event_handled(&ctx->stream, ctx->sendEventType);
        nc_stream_event(ctx);
    }
    nc_stream_ref_count_dec(ctx);
}

void nc_stream_send_packet(struct nc_stream_context* ctx, enum nabto_stream_next_event_type eventType)
{
    if (ctx->stopped) {
        return;
    }
    if (ctx->dtls == NULL) {
        nabto_stream_event_handled(&ctx->stream, eventType);
        nc_stream_event(ctx);
        return;
    }

    if (ctx->isSending) {
        return;
    }

    ctx->isSending = true;

    ctx->sendEventType = eventType;

    ctx->sendCtx.buffer = ctx->sendBuffer;

    uint8_t* start = ctx->sendBuffer;
    uint8_t* ptr = start;

    *ptr = (uint8_t)AT_STREAM;
    ptr++;

    ptr = var_uint_write_forward(ptr, ctx->streamId);

    size_t packetSize = nabto_stream_create_packet(&ctx->stream, ptr, NC_STREAM_SEND_BUFFER_SIZE+start-ptr, eventType);
    if (packetSize == 0) {
        // no packet to send
        ctx->isSending = false;
        return;
    }
    ctx->sendCtx.bufferSize = ptr-start+packetSize;
    ctx->sendCtx.cb = &nc_stream_dtls_send_callback;
    ctx->sendCtx.data = ctx;
    ctx->sendCtx.channelId = NP_DTLS_SRV_DEFAULT_CHANNEL_ID;
    np_error_code ec = ctx->pl->dtlsS.async_send_data(ctx->pl, ctx->dtls, &ctx->sendCtx);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "dtls send returned ec: %u", ec);
        nabto_stream_event_handled(&ctx->stream, eventType);
        if(np_event_queue_post_maybe_double(&ctx->pl->eq, ctx->ev)) {
            nc_stream_ref_count_inc(ctx);
        }
    } else {
        nc_stream_ref_count_inc(ctx);
    }
}

void nc_stream_event_queue_callback(void* data)
{
    struct nc_stream_context* stream = (struct nc_stream_context*)data;

    nc_stream_event(stream);

    nc_stream_ref_count_dec(stream);
}

// Called from streaming module when an event happens, e.g. there's
// data to be sent on the stream or it has been closed or data has
// been read.
void nc_stream_event_callback(enum nabto_stream_module_event event, void* data)
{
    struct nc_stream_context* ctx = (struct nc_stream_context*) data;
    if (ctx->stopped) {
        return;
    }
    if(np_event_queue_post_maybe_double(&ctx->pl->eq, ctx->ev)) {
        nc_stream_ref_count_inc(ctx);
    }
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



/************
 * Implementation of async user facing stream functions
 ************/

static void nc_stream_do_read(struct nc_stream_context* stream);
static void nc_stream_do_write_all(struct nc_stream_context* stream);
static np_error_code nc_stream_handle_close(struct nc_stream_context* stream);

void nc_stream_accept(struct nc_stream_context* stream)
{
    nabto_stream_set_application_event_callback(&stream->stream, &nc_stream_application_event_callback, stream);
    nabto_stream_accept(&stream->stream);
}

np_error_code nc_stream_async_accept(struct nc_stream_context* stream, nc_stream_callback callback, void* userData)
{
    if (stream->stopped) {
        return NABTO_EC_STOPPED;
    }

    if (stream->acceptCb != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    stream->acceptCb = callback;
    stream->acceptUserData = userData;
    nabto_stream_set_application_event_callback(&stream->stream, &nc_stream_application_event_callback, stream);
    nabto_stream_accept(&stream->stream);
    return NABTO_EC_OK;
}

np_error_code nc_stream_async_read_all(struct nc_stream_context* stream, void* buffer, size_t bufferLength, size_t* readLength, nc_stream_callback callback, void* userData)
{
    if (stream->stopped) {
        return NABTO_EC_STOPPED;
    }

    if (stream->readAllCb != NULL || stream->readSomeCb != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    stream->readAllCb = callback;
    stream->readUserData = userData;

    stream->readBuffer = buffer;
    stream->readBufferLength = bufferLength;
    stream->readLength = readLength;
    *stream->readLength = 0;
    nc_stream_do_read(stream);
    return NABTO_EC_OK;
}

np_error_code nc_stream_async_read_some(struct nc_stream_context* stream, void* buffer, size_t bufferLength, size_t* readLength, nc_stream_callback callback, void* userData)
{
    if (stream->stopped) {
        return NABTO_EC_STOPPED;
    }

    if (stream->readAllCb != NULL || stream->readSomeCb != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    stream->readSomeCb = callback;
    stream->readUserData = userData;

    stream->readBuffer = buffer;
    stream->readBufferLength = bufferLength;
    stream->readLength = readLength;
    *stream->readLength = 0;
    nc_stream_do_read(stream);
    return NABTO_EC_OK;
}

np_error_code nc_stream_async_write(struct nc_stream_context* stream, const void* buffer, size_t bufferLength, nc_stream_callback callback, void* userData)
{
    if (stream->stopped) {
        return NABTO_EC_STOPPED;
    }

    if (stream->writeCb != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    stream->writeCb = callback;
    stream->writeUserData = userData;

    stream->writeBuffer = buffer;
    stream->writeBufferLength = bufferLength;

    nc_stream_do_write_all(stream);
    return NABTO_EC_OK;
}

np_error_code nc_stream_async_close(struct nc_stream_context* stream, nc_stream_callback callback, void* userData)
{
    if (stream->stopped) {
        return NABTO_EC_STOPPED;
    }

    if (stream->closeCb != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    stream->closeCb = callback;
    stream->closeUserData = userData;
    np_error_code ec = nc_stream_handle_close(stream);
    if (ec != NABTO_EC_OK) {
        // If close failed, throw away the callback
        stream->closeCb = NULL;
        stream->closeUserData = NULL;
    }
    return ec;
}

void nc_stream_resolve_read(struct nc_stream_context* stream, np_error_code ec)
{
    stream->readLength = NULL;
    stream->readBuffer = NULL;
    stream->readBufferLength = 0;

    if (stream->readAllCb) {
        nc_stream_callback cb = stream->readAllCb;
        stream->readAllCb = NULL;
        cb(ec, stream->readUserData);
    } else if (stream->readSomeCb) {
        nc_stream_callback cb = stream->readSomeCb;
        stream->readSomeCb = NULL;
        cb(ec, stream->readUserData);
    } else {
        NABTO_LOG_ERROR(LOG, "Tried to resolve read futures which does not exist");
    }
}

void nc_stream_do_read(struct nc_stream_context* stream)
{
    if (!stream->readAllCb && !stream->readSomeCb) {
        // data available but no one wants it
        NABTO_LOG_TRACE(LOG, "Stream do read with no read future");
    } else {
        size_t readen;
        nabto_stream_status status = nabto_stream_read_buffer(&stream->stream, (uint8_t*)stream->readBuffer, stream->readBufferLength, &readen);
        if (status == NABTO_STREAM_STATUS_OK) {
            if (readen == 0) {
                // wait for a new event saying more data is ready.
            } else {
                *stream->readLength += readen;
                stream->readBuffer = ((uint8_t*)stream->readBuffer) + readen;
                stream->readBufferLength -= readen;
                if (stream->readAllCb) {
                    if (stream->readBufferLength == 0) {
                        nc_stream_resolve_read(stream, NABTO_EC_OK);
                    } else {
                        // read more until 0 or error
                        nc_stream_do_read(stream);
                    }
                } else if (stream->readSomeCb) {
                    nc_stream_resolve_read(stream, NABTO_EC_OK);
                } else {
                    // Still no future? we just checked this!
                    NABTO_LOG_ERROR(LOG, "Reached imposible stream state. Futures exist but dont");
                }
            }
        } else {
            nc_stream_resolve_read(stream, nc_stream_status_to_ec(status));
        }
    }
}
void nc_stream_do_write_all(struct nc_stream_context* stream)
{
    size_t written;
    nabto_stream_status status = nabto_stream_write_buffer(&stream->stream, stream->writeBuffer, stream->writeBufferLength, &written);
    if (status == NABTO_STREAM_STATUS_OK) {
        if (written == 0) {
            // would block
            return;
        } else if (written == stream->writeBufferLength) {
            nc_stream_callback cb = stream->writeCb;
            stream->writeCb = NULL;
            cb(NABTO_EC_OK, stream->writeUserData);
        } else {
            stream->writeBuffer = ((uint8_t*)stream->writeBuffer) + written;
            stream->writeBufferLength -= written;
            nc_stream_do_write_all(stream);
        }
    } else {
        nc_stream_callback cb = stream->writeCb;
        stream->writeCb = NULL;
        cb(nc_stream_status_to_ec(status), stream->writeUserData);
    }

}

np_error_code nc_stream_handle_close(struct nc_stream_context* stream)
{
    if (!stream->closeCb) {
        return NABTO_EC_OK;
    }
    nabto_stream_status status = nabto_stream_close(&stream->stream);
    if (status == NABTO_STREAM_STATUS_OK) {
        return NABTO_EC_OK;
    } else if (status == NABTO_STREAM_STATUS_CLOSED) {
        return NABTO_EC_CLOSED;
        nc_stream_callback cb = stream->closeCb;
        stream->closeCb = NULL;
        cb(NABTO_EC_OK, stream->closeUserData);
    } else {
        return nc_stream_status_to_ec(status);
        nc_stream_callback cb = stream->closeCb;
        stream->closeCb = NULL;
        cb(nc_stream_status_to_ec(status), stream->closeUserData);
    }
}

void nc_stream_application_event_callback(nabto_stream_application_event_type eventType, void* data)
{
    struct nc_stream_context* stream = data;
    switch(eventType) {
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_OPENED:
            if (stream->acceptCb) {
                nc_stream_callback cb = stream->acceptCb;
                stream->acceptCb = NULL;
                cb(NABTO_EC_OK, stream->acceptUserData);
            }
            break;
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_DATA_READY:
            nc_stream_do_read(stream);
            break;
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_DATA_WRITE:
            if (stream->writeCb) {
                nc_stream_do_write_all(stream);
            }
            break;
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_READ_CLOSED:
            nc_stream_do_read(stream);
            break;
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_WRITE_CLOSED:
            if (stream->closeCb) {
                nc_stream_callback cb = stream->closeCb;
                stream->closeCb = NULL;
                cb(NABTO_EC_OK, stream->closeUserData);
            }
            break;
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_CLOSED:
            if (stream->writeCb) {
                nc_stream_do_write_all(stream);
            }
            if (stream->acceptCb) {
                nc_stream_callback cb = stream->acceptCb;
                stream->acceptCb = NULL;
                cb(NABTO_EC_ABORTED, stream->acceptUserData);
            }
            nc_stream_do_read(stream);
            np_error_code ec = nc_stream_handle_close(stream);
            if (ec != NABTO_EC_OK && stream->closeCb) {
                nc_stream_callback cb = stream->closeCb;
                stream->closeCb = NULL;
                cb(ec, stream->closeUserData);
            }
            break;
        default:
            NABTO_LOG_ERROR(LOG, "Unknown stream application event type %s", nabto_stream_application_event_type_to_string(eventType));
    }
}

void nc_stream_stop(struct nc_stream_context* stream)
{
    if (stream->stopped) {
        return;
    }

    stream->stopped = true;
    if (nabto_stream_stop_should_send_rst(&stream->stream) && stream->dtls) {
        NABTO_LOG_TRACE(LOG, "Sending RST");
        nc_stream_manager_send_rst(stream->streamManager, stream->dtls, stream->streamId);
    }

    struct np_platform* pl = stream->pl;
    np_event_queue_cancel_event(&pl->eq, stream->timer);

    nc_stream_callback acceptCb = stream->acceptCb;
    stream->acceptCb = NULL;

    nc_stream_callback readAllCb = stream->readAllCb;
    stream->readAllCb = NULL;

    nc_stream_callback readSomeCb = stream->readSomeCb;
    stream->readSomeCb = NULL;

    nc_stream_callback writeCb = stream->writeCb;
    stream->writeCb = NULL;

    nc_stream_callback closeCb = stream->closeCb;
    stream->closeCb = NULL;

    if (acceptCb) {
        acceptCb(NABTO_EC_ABORTED, stream->acceptUserData);
    }
    if (readAllCb) {
        readAllCb(NABTO_EC_ABORTED, stream->readUserData);
    }
    if (readSomeCb) {
        readSomeCb(NABTO_EC_ABORTED, stream->readUserData);
    }
    if (writeCb) {
        writeCb(NABTO_EC_ABORTED, stream->writeUserData);
    }
    if (closeCb) {
        closeCb(NABTO_EC_ABORTED, stream->closeUserData);
    }

    stream->dtls = NULL;
    stream->streamId = 0;
}


void nc_stream_ref_count_inc(struct nc_stream_context* stream)
{
    stream->refCount++;
}

void nc_stream_ref_count_dec(struct nc_stream_context* stream)
{
    stream->refCount--;
    if (stream->refCount == 0) {
        nabto_stream_destroy(&stream->stream);
        nc_stream_free(stream);
    }
}
