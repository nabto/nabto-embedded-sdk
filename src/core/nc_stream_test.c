#include "nc_stream_manager.h"

#include <core/nc_client_connect.h>

#include <platform/np_platform.h>
#include <platform/np_unit_test.h>
#include <core/nc_tests.h>

#include <platform/np_logging.h>

#include <stdlib.h>

void nc_stream_test_send_to_dev(void* data);
void nc_stream_test_send_to_cli(void* data);


struct np_communication_buffer {
    uint8_t buf[1500];
};

struct nc_stream_test_context {
    struct np_platform cliPl;
    struct np_platform devPl;

    struct nc_client_connection cliConn;
    struct nc_stream_manager_context cliCtx;
    struct np_communication_buffer cliBuffer;
    uint16_t cliBufferSize;
    struct np_event cliEv;
    bool firstCliPacket;
    struct nabto_stream* cliStream;
    uint8_t cliTestBuffer[1500];

    struct nc_client_connection devConn;
    struct nc_stream_manager_context devCtx;
    struct np_communication_buffer devBuffer;
    uint16_t devBufferSize;
    struct np_event devEv;
    uint8_t devTestData[10];
    uint16_t devTestDataSize;
    struct nabto_stream* devStream;

};

struct nc_stream_test_context ctx;

// communication buffer impl
np_communication_buffer* nc_stream_test_allocate() { return (np_communication_buffer*)malloc(sizeof(struct np_communication_buffer)); }
void nc_stream_test_free(np_communication_buffer* buffer) {free(buffer);}
uint8_t* nc_stream_test_start(np_communication_buffer* buffer) { return buffer->buf; }
uint16_t nc_stream_test_size(np_communication_buffer* buffer) { return 1500; }



// DTLS SERVER TEST IMPL
np_error_code nc_stream_test_cli_dtls_srv_async_send_to(struct np_platform* pl, struct np_dtls_srv_connection* dtls,
                                                        uint8_t* buffer, uint16_t bufferSize,
                                                        np_dtls_send_to_callback cb, void* data)
{
    NABTO_LOG_ERROR(0, "Cli wants send: ");
    NABTO_LOG_BUF(0, buffer, bufferSize);
/*    if (ctx.firstCliPacket) {
        NABTO_LOG_ERROR(0, "Dropping first packet");
        ctx.firstCliPacket = false;
        return NABTO_EC_OK;
        }*/
    memcpy(ctx.cliBuffer.buf, buffer, bufferSize);
    ctx.cliBufferSize = bufferSize;
    np_event_queue_post(&ctx.cliPl, &ctx.cliEv, &nc_stream_test_send_to_dev, &ctx);
    return NABTO_EC_OK;
}
np_error_code nc_stream_test_dev_dtls_srv_async_send_to(struct np_platform* pl, struct np_dtls_srv_connection* dtls,
                                               uint8_t* buffer, uint16_t bufferSize,
                                               np_dtls_send_to_callback cb, void* data)
{
    NABTO_LOG_ERROR(0, "Dev wants send:");
    NABTO_LOG_BUF(0, buffer, bufferSize);
    memcpy(ctx.devBuffer.buf, buffer, bufferSize);
    ctx.devBufferSize = bufferSize;
    np_event_queue_post(&ctx.devPl, &ctx.devEv, &nc_stream_test_send_to_cli, &ctx);
    return NABTO_EC_OK;
}

// MODULE IMPL ENDS

void nc_stream_test_cli_application_event_callback(nabto_stream_application_event_type eventType, void* data)
{
    NABTO_LOG_ERROR(0, "Cli application event callback eventType: %s", nabto_stream_application_event_type_to_string(eventType));
    if (eventType == NABTO_STREAM_APPLICATION_EVENT_TYPE_DATA_READY) {
        size_t readen = 0;
        size_t written = 0;
        nabto_stream_read_buffer(ctx.cliStream, ctx.cliTestBuffer, 1500, &readen);
        if (readen > 0) {
            nabto_stream_write_buffer(ctx.cliStream, ctx.cliTestBuffer, readen, &written);
            NABTO_LOG_ERROR(0, "Cli application event wrote %u bytes", written);
        }
    }
}

void nc_stream_test_dev_application_event_callback(nabto_stream_application_event_type eventType, void* data)
{
    size_t written = 0;
    NABTO_LOG_ERROR(0, "Dev application event callback eventType: %s", nabto_stream_application_event_type_to_string(eventType));
    if (eventType == NABTO_STREAM_APPLICATION_EVENT_TYPE_OPENED) {
        nabto_stream_write_buffer(ctx.devStream, ctx.devTestData, ctx.devTestDataSize, &written);
        NABTO_LOG_ERROR(0, "Device wrote %u bytes", written);
    }
}

void nc_stream_test_send_to_dev(void* data)
{
    nc_stream_manager_handle_packet(&ctx.devCtx, &ctx.devConn, &ctx.cliBuffer, ctx.cliBufferSize);
}

void nc_stream_test_send_to_cli(void* data)
{
    nc_stream_manager_handle_packet(&ctx.cliCtx, &ctx.cliConn, &ctx.devBuffer, ctx.devBufferSize);
}

void nc_stream_test_listener_cb(struct nabto_stream* stream, void* data)
{
    NABTO_LOG_ERROR(0, "Test listener callback ");
    ctx.devStream = stream;
    nabto_stream_set_application_event_callback(stream, &nc_stream_test_dev_application_event_callback, &ctx);
    nabto_stream_accept(stream);
//    nabto_stream_write_buffer(stream, ctx.devTestData, ctx.devTestDataSize, &written);
//    NABTO_LOG_ERROR(0, "Device wrote %u bytes", written);
}

void nc_stream_test_syn_ack()
{
    memset(&ctx, 0, sizeof(struct nc_stream_test_context));

//    np_log_init();

    ctx.cliPl.buf.start = &nc_stream_test_start;
    ctx.cliPl.buf.allocate = &nc_stream_test_allocate;
    ctx.cliPl.buf.free = &nc_stream_test_free;
    ctx.cliPl.buf.size = &nc_stream_test_size;

    ctx.cliPl.dtlsS.async_send_to = &nc_stream_test_cli_dtls_srv_async_send_to;
    
    np_ts_init(&ctx.cliPl);

    ctx.devPl.buf.start = &nc_stream_test_start;
    ctx.devPl.buf.allocate = &nc_stream_test_allocate;
    ctx.devPl.buf.free = &nc_stream_test_free;
    ctx.devPl.buf.size = &nc_stream_test_size;

    ctx.devPl.dtlsS.async_send_to = &nc_stream_test_dev_dtls_srv_async_send_to;

    np_ts_init(&ctx.devPl);


    ctx.firstCliPacket = true;
    memcpy(ctx.devTestData, "TEST_DATA", 10);
    ctx.devTestDataSize = 10;
    
    nc_stream_manager_init(&ctx.cliCtx, &ctx.cliPl);
    nc_stream_manager_init(&ctx.devCtx, &ctx.devPl);

    nc_stream_manager_set_listener(&ctx.devCtx, &nc_stream_test_listener_cb, &ctx);

    ctx.cliStream = &ctx.cliCtx.streams[0].stream;
    nc_stream_init(&ctx.cliPl, &ctx.cliCtx.streams[0], 42, ctx.cliCtx.streams[0].dtls, &ctx.cliCtx);
    nabto_stream_set_application_event_callback(ctx.cliStream, &nc_stream_test_cli_application_event_callback, &ctx);
    nabto_stream_open(ctx.cliStream, 4242);

    while(
        np_event_queue_has_ready_event(&ctx.cliPl) ||
        np_event_queue_has_ready_event(&ctx.devPl) //||
//        np_event_queue_has_timed_event(&ctx.cliPl) ||
//        np_event_queue_has_timed_event(&ctx.devPl)
        ) {
        
        np_event_queue_execute_all(&ctx.cliPl);
        np_event_queue_execute_all(&ctx.devPl);
    }

    NABTO_TEST_CHECK(true);
}


void nc_stream_tests()
{
    nc_stream_test_syn_ack();
}
