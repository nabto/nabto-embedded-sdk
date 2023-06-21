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

    nc_stream_callback readAllCb = stream->virt.readAllCb;
    stream->virt.readAllCb = NULL;

    nc_stream_callback readSomeCb = stream->virt.readSomeCb;
    stream->virt.readSomeCb = NULL;

    nc_stream_callback writeCb = stream->virt.writeCb;
    stream->virt.writeCb = NULL;

    nc_stream_callback closeCb = stream->virt.closeCb;
    stream->virt.closeCb = NULL;

    if (readAllCb) {
        readAllCb(NABTO_EC_ABORTED, stream->virt.readUserData);
    }
    if (readSomeCb) {
        readSomeCb(NABTO_EC_ABORTED, stream->virt.readUserData);
    }
    if (writeCb) {
        writeCb(NABTO_EC_ABORTED, stream->virt.writeUserData);
    }
    if (closeCb) {
        closeCb(NABTO_EC_ABORTED, stream->virt.closeUserData);
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



void nc_virtual_stream_server_read(struct nc_stream_context* stream)
{

}

void nc_virtual_stream_client_async_write(struct nc_stream_context* stream, const void* buffer, size_t bufferLength, struct np_completion_event* writeEv)
{
    return;
}

