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

struct nc_stream_context {
    struct np_platform* pl;
    struct nabto_stream stream;
    uint64_t streamId;
    struct np_dtls_srv_connection* dtls;
    struct nc_stream_manager_context* streamManager;
    struct np_dtls_srv_send_context sendCtx;
    struct np_event ev;
    bool active;

    nabto_stream_stamp currentExpiry;
    uint32_t negativeCount;
    struct np_timed_event timer;

    np_communication_buffer* sendBuffer;
    uint16_t sendBufferSize;
};

void nc_stream_init(struct np_platform* pl, struct nc_stream_context* ctx, uint64_t streamId, struct np_dtls_srv_connection* dtls, struct nc_stream_manager_context* streamManager);

void nc_stream_handle_packet(struct nc_stream_context* ctx, uint8_t* buffer, uint16_t bufferSize);

void nc_stream_remove_connection(struct nc_stream_context* ctx);

np_error_code nc_stream_status_to_ec(nabto_stream_status status);

#endif // NC_STREAM_H
