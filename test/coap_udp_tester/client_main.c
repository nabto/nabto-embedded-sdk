#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <core/nc_coap_client.h>
#include <test_platform/test_platform.h>

#include <stdlib.h>

struct np_platform* pl;
struct nc_coap_client_context coap;
struct np_udp_send_context sendCtx;
np_dtls_send_to_callback dtlsCb;
void* dtlsData;

void udpSendCb(const np_error_code ec, void* data)
{
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "Socket error: %s", np_error_code_to_string(ec));
        exit(1);
    }
    NABTO_LOG_ERROR(0, "Socket send Succeeded");
    dtlsCb(NABTO_EC_OK, dtlsData);
}

np_error_code dtlsSendTo(struct np_platform* plIn, struct np_dtls_cli_context* ctx, uint8_t channelId,
                         uint8_t* buffer, uint16_t bufferSize,
                         np_dtls_send_to_callback cb, void* data)
{
    NABTO_LOG_INFO(0, "Send to UDP");
    memcpy(pl->buf.start(sendCtx.buffer), buffer, bufferSize);
    sendCtx.bufferSize = bufferSize;
    dtlsCb = cb;
    dtlsData = data;
    pl->udp.async_send_to(&sendCtx);
    return NABTO_EC_OK;
}

void udpRecvCb(const np_error_code ec, struct np_udp_endpoint inEp,
               struct np_communication_buffer* buffer, uint16_t bufferSize,
               void* data)
{
    NABTO_LOG_INFO(0, "UDP receive");
    sendCtx.ep = inEp;
    nc_coap_client_handle_packet(&coap, buffer, bufferSize, NULL);
    pl->udp.async_recv_from(sendCtx.sock, &udpRecvCb, NULL);
}

void udpCreatedCb(const np_error_code ec, void* data)
{

    pl->udp.async_recv_from(sendCtx.sock, &udpRecvCb, NULL);
}

void requestEndHandler(struct nabto_coap_client_request* req, void* data)
{
    const uint8_t* payload = malloc(1500);
    size_t payloadLen = 1500;
    struct nabto_coap_client_response* res = nabto_coap_client_request_get_response(req);
    if (!res) {
        NABTO_LOG_ERROR(0, "No COAP response available");
        exit(1);
    }
    uint8_t code = nabto_coap_client_response_get_code(res);
    nabto_coap_client_response_get_payload(res, &payload, &payloadLen);
    NABTO_LOG_INFO(0, "COAP response with code: %d, and payload: %s", code, payload);
    exit(0);
}

int main()
{
    struct test_platform tp;
    const char* path = "helloworld";
    test_platform_init(&tp);

    pl = &tp.pl;

    pl->dtlsC.async_send_to = &dtlsSendTo;

    nc_coap_client_init(pl, &coap);

    sendCtx.buffer = pl->buf.allocate();
    sendCtx.cb = &udpSendCb;
    sendCtx.cbData = NULL;
    sendCtx.ep.port = 4242;
    sendCtx.ep.ip.type = NABTO_IPV4;

    sendCtx.ep.ip.v4.addr[0] = 127;
    sendCtx.ep.ip.v4.addr[1] = 0;
    sendCtx.ep.ip.v4.addr[2] = 0;
    sendCtx.ep.ip.v4.addr[3] = 1;

    pl->udp.create(pl, &sendCtx.sock);
    pl->udp.async_bind(sendCtx.sock, &udpCreatedCb, NULL);

    struct nabto_coap_client_request* req = nabto_coap_client_request_new(nc_coap_client_get_client(&coap),
                                                                          NABTO_COAP_CODE_GET,
                                                                          1,
                                                                          &path,
                                                                          &requestEndHandler,
                                                                          NULL, NULL);
    nabto_coap_client_request_send(req);

    test_platform_run(&tp);
}
