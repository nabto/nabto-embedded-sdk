#ifndef NC_STREAM_H
#define NC_STREAM_H

#include <platform/np_platform.h>
#include <platform/np_dtls_srv.h>

#include <streaming/nabto_stream.h>
#include <streaming/nabto_stream_interface.h>
#include <streaming/nabto_stream_protocol.h>
#include <streaming/nabto_stream_packet.h>
#include <streaming/nabto_stream_window.h>
#include <streaming/nabto_stream_util.h>
#include <streaming/nabto_stream_memory.h>
#include <streaming/nabto_stream_log_helper.h>

struct nc_stream_manager_context;

typedef void (*nc_stream_callback)(const np_error_code ec, void* userData);

#define NC_STREAM_SEND_BUFFER_SIZE 1150

struct nc_stream_context {
    struct np_platform* pl;
    struct nabto_stream stream;
    uint64_t streamId;
    struct np_dtls_srv_connection* dtls;
    struct nc_stream_manager_context* streamManager;
    struct np_event* ev;
    bool active;
    uint64_t connectionRef;

    nabto_stream_stamp currentExpiry;
    uint32_t negativeCount;
    struct np_timed_event* timer;

    // user facing stream data
    nc_stream_callback acceptCb;
    void* acceptUserData;
    nc_stream_callback readAllCb;
    nc_stream_callback readSomeCb;
    void* readUserData;
    size_t* readLength;
    void* readBuffer;
    size_t readBufferLength;

    nc_stream_callback writeCb;
    void* writeUserData;
    const void* writeBuffer;
    size_t writeBufferLength;
    nc_stream_callback closeCb;
    void* closeUserData;

    bool isSending;
    struct np_dtls_srv_send_context sendCtx;
    uint8_t sendBuffer[NC_STREAM_SEND_BUFFER_SIZE];
    enum nabto_stream_next_event_type sendEventType;
};



void nc_stream_init(struct np_platform* pl, struct nc_stream_context* ctx, uint64_t streamId, struct np_dtls_srv_connection* dtls, struct nc_stream_manager_context* streamManager, uint64_t connectionRef);

void nc_stream_handle_packet(struct nc_stream_context* ctx, uint8_t* buffer, uint16_t bufferSize);

void nc_stream_handle_connection_closed(struct nc_stream_context* ctx);

np_error_code nc_stream_status_to_ec(nabto_stream_status status);


void nc_stream_accept(struct nc_stream_context* stream);
np_error_code nc_stream_async_accept(struct nc_stream_context* stream, nc_stream_callback callback, void* userData);
np_error_code nc_stream_async_read_all(struct nc_stream_context* stream, void* buffer, size_t bufferLength, size_t* readLength, nc_stream_callback callback, void* userData);
np_error_code nc_stream_async_read_some(struct nc_stream_context* stream, void* buffer, size_t bufferLength, size_t* readLength, nc_stream_callback callback, void* userData);
np_error_code nc_stream_async_write(struct nc_stream_context* stream, const void* buffer, size_t bufferLength, nc_stream_callback callback, void* userData);
np_error_code nc_stream_async_close(struct nc_stream_context* stream, nc_stream_callback callback, void* userData);

/**
 * Abort a stream, means close all outstanding async operations. And
 * if neccessary mark the stream as aborted. If not all data was read
 * or wrote.
 */
void nc_stream_abort(struct nc_stream_context* stream);

/**
 * Release ownership of a streaming resource. The resource is then
 * cleaned up by the stream manager module.
 */
void nc_stream_release(struct nc_stream_context* stream);

#endif // NC_STREAM_H
