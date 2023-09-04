#include "tcp_tunnel_coap.h"
#include "tcp_tunnel_ptz_state.h"

#include <cbor.h>
#include <stdlib.h>

static void handle_request(struct tunnel_coap_handler* handler, NabtoDeviceCoapRequest* request);

//////////////////////////////////////////////////////////////////////////////////////
/// [COAP_ENDPOINT_TEMPLATE]: Endpoint definition
///
/// Add CoAP endpoint definition here and reference it from tunnel_coap_init_handlers()
/// in tcp_tunnel_coap.c. Note the path to the endpoint and the method.
NabtoDeviceError tunnel_ptz_get_state_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server)
{
    const char* paths[] = { "ptz", NULL };
    return tunnel_coap_handler_init(handler, device, tunnel_coap_server, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}

//////////////////////////////////////////////////////////////////////////////////////
/// [COAP_ENDPOINT_TEMPLATE]: Implementation
///
/// Add CoAP endpoint implementation here.
void handle_request(struct tunnel_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    nabto_device_coap_response_set_code(request, 205);
    nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_JSON);
    char jsonTemplate[] = "{\"pan\": %.3f, \"tilt\": %.3f, \"zoom\": %.3f}";
    char response[128];
    struct ptz_state* state = handler->tunnel_coap_server->state;
    snprintf(response, 128, jsonTemplate, state->pan, state->tilt, state->zoom);
    NabtoDeviceError ec = nabto_device_coap_response_set_payload(request, response, strlen(response));
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
    } else {
        nabto_device_coap_response_ready(request);
    }
}


