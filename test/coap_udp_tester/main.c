#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/communication_buffer/nm_unix_communication_buffer.h>
#include <core/nc_coap.h>

#include <stdlib.h>

struct np_platform pl;
struct nc_coap_context coap;
struct np_udp_send_context sendCtx;

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
}

np_error_code dtlsSendTo(struct np_platform* plIn, struct np_dtls_srv_connection* ctx,
                         struct np_dtls_srv_send_context* send)
//                                   uint8_t* buffer, uint16_t bufferSize,
//                                   np_dtls_send_to_callback cb, void* data)
{
    memcpy(pl.buf.start(sendCtx.buffer), send->buffer, send->bufferSize);
    sendCtx.bufferSize = send->bufferSize;
    pl.udp.async_send_to(&sendCtx);
    return NABTO_EC_OK;
}

void udpRecvCb(const np_error_code ec, struct np_udp_endpoint inEp,
               np_communication_buffer* buffer, uint16_t bufferSize,
               void* data)
{
    sendCtx.ep = inEp;
    nc_coap_handle_packet(&coap, NULL, buffer, bufferSize);
    pl.udp.async_recv_from(sendCtx.sock, &udpRecvCb, NULL);
}

void udpCreatedCb(const np_error_code ec, np_udp_socket* socket, void* data)
{
    sendCtx.sock = socket;
    pl.udp.async_recv_from(socket, &udpRecvCb, NULL);
}

void handleHelloReq(struct nabto_coap_server_request* request, void* userData)
{
    static const char* helloWorld = "hello world";
    struct nabto_coap_server_response* response = nabto_coap_server_create_response(request);
    nabto_coap_server_response_set_code(response, (nabto_coap_code)NABTO_COAP_CODE(2,05));
    nabto_coap_server_response_set_content_format(response, NABTO_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);
    nabto_coap_server_response_set_payload(response, (uint8_t*)helloWorld, strlen(helloWorld));
    nabto_coap_server_response_ready(response);
}

int main()
{
    int nfds;
    np_platform_init(&pl);
    np_log_init();
    nm_unix_comm_buf_init(&pl);
    np_ts_init(&pl);
    np_udp_init(&pl);
    
    pl.dtlsS.async_send_to = &dtlsSendTo;

    nc_coap_init(&pl, &coap);

    sendCtx.buffer = pl.buf.allocate();
    sendCtx.cb = &udpSendCb;
    sendCtx.cbData = NULL;
    
    pl.udp.async_bind_port(4242, &udpCreatedCb, NULL);

    nabto_coap_server_add_resource(nc_coap_get_server(&coap), NABTO_COAP_CODE_GET, "helloworld", &handleHelloReq, NULL);
    
    while(true) {
        np_event_queue_execute_all(&pl);
        if (np_event_queue_has_timed_event(&pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&pl);
            nfds = pl.udp.timed_wait(ms);
        } else {
            nfds = pl.udp.inf_wait();
        }
        pl.udp.read(nfds);
    }
   
}
