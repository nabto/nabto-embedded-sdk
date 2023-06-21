#include "nc_virtual_stream.h"

#include <core/nc_connection.h>
#include <core/nc_stream_manager.h>

#include <platform/np_event_queue_wrapper.h>
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_STREAM


np_error_code nc_virtual_stream_init(struct np_platform* pl, struct nc_stream_context* ctx, struct nc_connection* conn, struct nc_stream_manager_context* streamManager, uint32_t port, struct np_completion_event* openedEv)
{
    // Start refCount at 1 to ensure stream is not freed until user freed the virtual stream
    ctx->refCount = 1;
    ctx->stopped = false;
    ctx->conn = conn;
    ctx->streamManager = streamManager;
    ctx->pl = pl;
    ctx->isSending = false;
    ctx->connectionRef = conn->connectionRef;
    ctx->accepted = false;
    ctx->isVirtual = true;
    ctx->virt.port = port;
    ctx->virt.openedEv = openedEv;
    ctx->virt.stopped = false;

    nc_stream_manager_ready_for_accept(ctx->streamManager, ctx);
    return NABTO_EC_OK;
}

void nc_virtual_stream_client_stop(struct nc_stream_context* stream)
{
    if (stream->virt.stopped) {
        return;
    }

    stream->virt.stopped = true;

    if (stream->virt.openedEv) {
        np_completion_event_resolve(stream->virt.openedEv, NABTO_EC_ABORTED);
        stream->virt.openedEv = NULL;
    }

    if (stream->virt.readAllEv) {
        np_completion_event_resolve(stream->virt.readAllEv, NABTO_EC_ABORTED);
        stream->virt.readAllEv = NULL;
    }

    if (stream->virt.readSomeEv) {
        np_completion_event_resolve(stream->virt.readSomeEv, NABTO_EC_ABORTED);
        stream->virt.readSomeEv = NULL;
    }

    if (stream->virt.writeEv) {
        np_completion_event_resolve(stream->virt.writeEv, NABTO_EC_ABORTED);
        stream->virt.writeEv = NULL;
    }

    if (stream->virt.closeEv) {
        np_completion_event_resolve(stream->virt.closeEv, NABTO_EC_ABORTED);
        stream->virt.closeEv = NULL;
    }

    nc_stream_resolve_read(stream, NABTO_EC_ABORTED);
}


void nc_virtual_stream_server_accepted(struct nc_stream_context* stream)
{
    if (stream->virt.openedEv) {
        np_completion_event_resolve(stream->virt.openedEv, NABTO_EC_OK);
        stream->virt.openedEv = NULL;
    }
    if (stream->acceptEv) {
        np_completion_event_resolve(stream->acceptEv, NABTO_EC_OK);
        stream->acceptEv = NULL;
    }
}


void nc_virtual_stream_destroy(struct nc_stream_context* stream)
{
    nc_stream_ref_count_dec(stream);
}


void nc_virtual_stream_do_write(struct nc_stream_context* stream)
{
    if (stream->readAllEv != NULL || stream->readSomeEv != NULL) {
        // Server read is ready, copy data
        size_t readen = stream->virt.writeBufferLength > stream->readBufferLength ? stream->readBufferLength : stream->virt.writeBufferLength;
        memcpy(stream->readBuffer, stream->virt.writeBuffer, readen);
        *stream->readLength += readen;

        if (stream->virt.writeBufferLength > stream->readBufferLength) {
            // store writeEv and resolve read
            stream->virt.writeBuffer = ((uint8_t*)stream->virt.writeBuffer) + readen;
            stream->virt.writeBufferLength -= readen;
            nc_stream_resolve_read(stream, NABTO_EC_OK);
        }
        else if (stream->virt.writeBufferLength < stream->readBufferLength &&
            stream->readAllEv != NULL) {
            // update readBuffer and resolve write

            stream->readBuffer = ((uint8_t*)stream->readBuffer) + readen;
            stream->readBufferLength -= readen;
            np_completion_event_resolve(stream->virt.writeEv, NABTO_EC_OK);
            stream->virt.writeBuffer = NULL;
            stream->virt.writeBufferLength = 0;
            stream->virt.writeEv = NULL;
        }
        else {
            // bufferLength == readBufferLength ||
            // bufferLength < readBufferLength && readSomeEv != NULL
            // resolve both
            np_completion_event_resolve(stream->virt.writeEv, NABTO_EC_OK);
            stream->virt.writeBuffer = NULL;
            stream->virt.writeBufferLength = 0;
            stream->virt.writeEv = NULL;
            nc_stream_resolve_read(stream, NABTO_EC_OK);
        }
    }
}


void nc_virtual_stream_server_read(struct nc_stream_context* stream)
{
    if (stream->virt.writeEv != NULL){
        nc_virtual_stream_do_write(stream);
    }
}

void nc_virtual_stream_client_async_write(struct nc_stream_context* stream, const void* buffer, size_t bufferLength, struct np_completion_event* writeEv)
{
    stream->virt.writeEv = writeEv;
    stream->virt.writeBuffer = buffer;
    stream->virt.writeBufferLength = bufferLength;
    nc_virtual_stream_do_write(stream);
}

