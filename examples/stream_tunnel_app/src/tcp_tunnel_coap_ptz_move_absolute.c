#include "tcp_tunnel_coap.h"
#include "tcp_tunnel_ptz_state.h"

#include <cbor.h>
#include <stdlib.h>
#include <cjson/cJSON.h>
#include <nn/log.h>

static const char* LOGM = "tunnel_coap";

static void handle_request(struct tunnel_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError tunnel_ptz_move_absolute_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server) 
{
    const char* paths[] = { "ptz", "absolute", NULL };
    return tunnel_coap_handler_init(handler, device, tunnel_coap_server, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

bool get_number(double* result, cJSON* json, const char* key)
{
    if (!cJSON_HasObjectItem(json, key)) {
        return false;
    }
    if (!cJSON_IsNumber(cJSON_GetObjectItem(json, key))) {
        return false;
    }
    *result = cJSON_GetObjectItem(json, key)->valuedouble;
    return true;
}

void handle_request(struct tunnel_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
   uint16_t contentFormat;
   NabtoDeviceError ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_JSON) {
        nabto_device_coap_error_response(request, 400, "Invalid Content Format");
        return;
    }
    void* payload;
    size_t payloadSize;
    if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 400, "Missing payload");
        return;
    }

    cJSON* json = cJSON_Parse((const char*)payload);
    if (json == NULL) {
        const char* error = cJSON_GetErrorPtr();
        if (error != NULL) {
            NN_LOG_ERROR(handler->tunnel_coap_server->logger, LOGM, "JSON parse error: %s", error);
            return;
        }
    }

    if (!get_number(&handler->tunnel_coap_server->state->pan, json, "pan")) {
        nabto_device_coap_error_response(request, 400, "Missing or invalid pan value");
        return;
    }
    if (!get_number(&handler->tunnel_coap_server->state->tilt, json, "tilt")) {
        nabto_device_coap_error_response(request, 400, "Missing or invalid tilt value");
        return;
    }
    if (!get_number(&handler->tunnel_coap_server->state->zoom, json, "zoom")) {
        nabto_device_coap_error_response(request, 400, "Missing or invalid zoom value");
        return;
    }

    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
}


