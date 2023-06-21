#ifndef NC_STREAM_H
#define NC_STREAM_H

#include <platform/np_platform.h>
#include <platform/np_dtls_cli.h>

#include <streaming/nabto_stream.h>
#include <streaming/nabto_stream_interface.h>
#include <streaming/nabto_stream_protocol.h>
#include <streaming/nabto_stream_packet.h>
#include <streaming/nabto_stream_window.h>
#include <streaming/nabto_stream_util.h>
#include <streaming/nabto_stream_memory.h>
#include <streaming/nabto_stream_log_helper.h>

struct nc_stream_manager_context;
struct nc_client_connection;

typedef void (*nc_stream_callback)(const np_error_code ec, void* userData);

#define NC_STREAM_SEND_BUFFER_SIZE 1150

struct nc_virtual_stream_context {
    uint32_t port;
    bool stopped;

    struct np_completion_event* openedEv;

    struct np_completion_event* readAllEv;
    struct np_completion_event* readSomeEv;
    size_t* readLength;
    void* readBuffer;
    size_t readBufferLength;

    struct np_completion_event* writeEv;
    const void* writeBuffer;
    size_t writeBufferLength;

    struct np_completion_event* closeEv;
};

struct nc_stream_context {
    struct np_platform* pl;
    struct nn_llist_node streamsNode;
    struct nabto_stream stream;
    uint64_t streamId;
    struct nc_connection* conn;
    struct nc_stream_manager_context* streamManager;
    struct np_event* ev;
    bool stopped;
    uint64_t connectionRef;
    bool isVirtual;
    struct nc_virtual_stream_context virt;

    nabto_stream_stamp currentExpiry;
    uint32_t negativeCount;
    struct np_event* timer;

    // user facing stream data
    struct np_completion_event* acceptEv;

    struct np_completion_event* readSomeEv;
    struct np_completion_event* readAllEv;
    size_t* readLength;
    void* readBuffer;
    size_t readBufferLength;

    struct np_completion_event* writeEv;
    const void* writeBuffer;
    size_t writeBufferLength;
    nc_stream_callback closeCb;
    void* closeUserData;

    bool isSending;
    struct np_dtls_send_context sendCtx;
    uint8_t sendBuffer[NC_STREAM_SEND_BUFFER_SIZE];
    enum nabto_stream_next_event_type sendEventType;
    size_t refCount;
    bool accepted;
};

void nc_stream_ref_count_inc(struct nc_stream_context* stream);
void nc_stream_ref_count_dec(struct nc_stream_context* stream);

// Initialize a new stream. Called by stream_manager.
np_error_code nc_stream_init(struct np_platform* pl, struct nc_stream_context* ctx, uint64_t streamId, uint64_t nonce, struct nc_connection* conn, struct nc_stream_manager_context* streamManager, uint64_t connectionRef, struct nn_log* logger);


void nc_stream_handle_packet(struct nc_stream_context* ctx, uint8_t* buffer, uint16_t bufferSize);
void nc_stream_handle_virtual_data(struct nc_stream_context* stream, const void* buffer, size_t bufferLength, nc_stream_callback callback, void* userData);

void nc_stream_handle_connection_closed(struct nc_stream_context* ctx);

np_error_code nc_stream_status_to_ec(nabto_stream_status status);


void nc_stream_accept(struct nc_stream_context* stream);
void nc_stream_async_accept(struct nc_stream_context* stream, struct np_completion_event* acceptEv);
void nc_stream_async_read_all(struct nc_stream_context* stream, void* buffer, size_t bufferLength, size_t* readLength, struct np_completion_event* readAllEv);
void nc_stream_async_read_some(struct nc_stream_context* stream, void* buffer, size_t bufferLength, size_t* readLength, struct np_completion_event* readSomeEv);
void nc_stream_async_write(struct nc_stream_context* stream, const void* buffer, size_t bufferLength, struct np_completion_event* writeEv);
np_error_code nc_stream_async_close(struct nc_stream_context* stream, nc_stream_callback callback, void* userData);

void nc_stream_resolve_read(struct nc_stream_context* stream, np_error_code ec);


/**
 * Release ownership of a streaming resource. The resource is then
 * cleaned up by the stream manager module.
 */
void nc_stream_stop(struct nc_stream_context* stream);

/**
 * stop and free a streaming resource
 */
void nc_stream_destroy(struct nc_stream_context* stream);


#endif // NC_STREAM_H
