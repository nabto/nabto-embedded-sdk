#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <core/nc_coap_server.h>
#include <test_platform/test_platform.h>

#include <stdlib.h>

struct np_platform* pl;
struct nc_coap_server_context coap;
struct np_udp_send_context sendCtx;
np_dtls_send_to_callback dtlsCb;
void* dtlsData;

struct np_dtls_srv_connection* nc_client_connect_get_dtls_connection(struct nc_client_connection* conn)
{
    return (struct np_dtls_srv_connection*)&coap;
}

void udpSendCb(const np_error_code ec, void* data)
{
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "Socket error: %s", np_error_code_to_string(ec));
        exit(1);
    }
    NABTO_LOG_ERROR(0, "Socket send Succeeded");
    dtlsCb(NABTO_EC_OK, dtlsData);
}

np_error_code dtlsSendTo(struct np_platform* plIn, struct np_dtls_srv_connection* ctx,
                         struct np_dtls_srv_send_context* send)
//                                   uint8_t* buffer, uint16_t bufferSize,
//                                   np_dtls_send_to_callback cb, void* data)
{
    NABTO_LOG_INFO(0, "Send to UDP");
    memcpy(pl->buf.start(sendCtx.buffer), send->buffer, send->bufferSize);
    sendCtx.bufferSize = send->bufferSize;
    dtlsCb = send->cb;
    dtlsData = send->data;
    pl->udp.async_send_to(&sendCtx);
    return NABTO_EC_OK;
}

void udpRecvCb(const np_error_code ec, struct np_udp_endpoint inEp,
               np_communication_buffer* buffer, uint16_t bufferSize,
               void* data)
{
    NABTO_LOG_INFO(0, "UDP receive");
    sendCtx.ep = inEp;
    nc_coap_server_handle_packet(&coap, NULL, buffer, bufferSize);
    pl->udp.async_recv_from(sendCtx.sock, &udpRecvCb, NULL);
}

void udpCreatedCb(const np_error_code ec, void* data)
{
    pl->udp.async_recv_from(sendCtx.sock, &udpRecvCb, NULL);
}

void handleHelloReq(struct nabto_coap_server_request* request, void* userData)
{
    NABTO_LOG_INFO(0, "COAP hello world");
    static const char* helloWorld = "hello world";
    nabto_coap_server_response_set_code(request, (nabto_coap_code)NABTO_COAP_CODE(2,05));
    nabto_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);
    nabto_coap_error err = nabto_coap_server_response_set_payload(request, (uint8_t*)helloWorld, strlen(helloWorld));
    if (err != NABTO_COAP_ERROR_OK) {
        NABTO_LOG_ERROR(0, "could not set response payload with: %u, only possible should be OOM: %u", err, NABTO_COAP_ERROR_OUT_OF_MEMORY);
        exit(1);
    }
    // On errors we should still clean up the request
    nabto_coap_server_response_ready(request);
    nabto_coap_server_request_free(request);
}

int main()
{
    struct test_platform tp;
    test_platform_init(&tp);
    pl = &tp.pl;

    pl->dtlsS.async_send_data = &dtlsSendTo;

    nc_coap_server_init(pl, &coap);

    sendCtx.buffer = pl->buf.allocate();
    sendCtx.cb = &udpSendCb;
    sendCtx.cbData = NULL;

    pl->udp.create(pl, &sendCtx.sock);
    pl->udp.async_bind_port(sendCtx.sock, 4242, &udpCreatedCb, NULL);

    nabto_coap_error err = nabto_coap_server_add_resource(nc_coap_server_get_server(&coap), NABTO_COAP_CODE_GET, (const char*[]){"helloworld", NULL}, &handleHelloReq, NULL);
    if (err != NABTO_COAP_ERROR_OK) {
        NABTO_LOG_ERROR(0, "Failed to add resource with: %d", err);
        exit(1);
    }

    test_platform_run(&tp);
}
