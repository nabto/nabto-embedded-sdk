#include "tcp_tunnel_coap.h"
#include "tcp_tunnel_ptz_state.h"

#include <cbor.h>
#include <stdlib.h>

static void handle_request(struct tunnel_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError tunnel_ptz_get_state_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server) 
{
    const char* paths[] = { "ptz", NULL };
    return tunnel_coap_handler_init(handler, device, tunnel_coap_server, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}

void handle_request(struct tunnel_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    nabto_device_coap_response_set_code(request, 205);
    nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_JSON);
    char jsonTemplate[] = "{\"tilt\": %.3f, \"pan\": %.3f, \"zoom\": %.3f, \"moving\": %s}";
    char response[128];
    struct ptz_state* state = handler->tunnel_coap_server->state;
    snprintf(response, 128, jsonTemplate, state->tilt, state->pan, state->zoom, state->moving ? "true" : "false");
    NabtoDeviceError ec = nabto_device_coap_response_set_payload(request, response, strlen(response));
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
    } else {
        nabto_device_coap_response_ready(request);
    }
}


