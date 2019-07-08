#include "heatpump_application.h"
#include "nabto/nabto_device.h"
#include "nabto/nabto_device_experimental.h"

#include <cjson/cJSON.h>

#include <stdlib.h>
#include <stdbool.h>



struct heatpump_application_state* heatpump_application_state_new()
{
    struct heatpump_application_state* state = (struct heatpump_application_state*)malloc(sizeof(struct heatpump_application_state));

    state->powerState = HEATPUMP_POWER_STATE_ON;
    state->roomTemperature = 19;
    state->target = 23;
    state->mode = HEATPUMP_MODE_HEAT;
    return state;
}

void heatpump_application_state_free(struct heatpump_application_state* state)
{
    free(state);
}

void heatpump_coap_send_error(NabtoDeviceCoapRequest* request, uint16_t code, const char* message)
{
     NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
     nabto_device_coap_response_set_code(response, code);
     nabto_device_coap_response_set_content_format(response, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);
     nabto_device_coap_response_set_payload(response, message, strlen(message));
     nabto_device_coap_response_ready(response);
}

void heatpump_coap_send_ok(NabtoDeviceCoapRequest* request, uint16_t code)
{
     NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
     nabto_device_coap_response_set_code(response, code);
     nabto_device_coap_response_ready(response);
}

// return true if action was allowed
bool heatpump_coap_check_action(NabtoDeviceCoapRequest* request, const char* action)
{
    NabtoDeviceIamEnv* iamEnv = nabto_device_iam_env_from_coap_request(request);

    NabtoDeviceIamEffect effect = nabto_device_iam_check_action(iamEnv, action);
    nabto_device_iam_env_free(iamEnv);
    if (effect == NABTO_DEVICE_IAM_EFFECT_ALLOW) {
        return true;
    } else {
        // deny
        heatpump_coap_send_error(request, 403, "Unauthorized");
        return false;
    }
}

cJSON* heatpump_parse_json_request(NabtoDeviceCoapRequest* request)
{
    uint16_t contentFormat;
    NabtoDeviceError ec;
    ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_JSON) {
        heatpump_coap_send_error(request, 400, "Invalid Content Format");
        return NULL;
    }

    void* payload;
    size_t payloadSize;
    if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
        heatpump_coap_send_error(request, 400, "Missing payload");
        return NULL;
    }

    cJSON* root = cJSON_Parse((const char*)payload);
    if (root == NULL) {
        heatpump_coap_send_error(request, 400, "Could not parse json");
        return NULL;
    }
    return root;
}

// Change heatpump power state (turn it on or off)
/**
 * Coap POST /heatpump/power,
 * Request, ContentFormat application/json
 * {
 *   "power": "ON" | "OFF"
 * }
 * Response, 200,
 */
void heatpump_set_state(NabtoDeviceCoapRequest* request, void* userData)
{
    struct heatpump_application_state* application = (struct heatpump_application_state*)userData;

    if (!heatpump_coap_check_action(request, "heatpump:SetPower")) {
        return;
    }

    cJSON* root = heatpump_parse_json_request(request);
    if (root == NULL) {
        return;
    }
    char* power = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(root, "power"));
    if (power == NULL) {
        heatpump_coap_send_error(request, 400, "Could not parse json");
    } else {
        bool unknown = false;
        if (strcmp(power, "ON") == 0) {
            application->powerState = HEATPUMP_POWER_STATE_ON;
        } else if (strcmp(power, "OFF") == 0) {
            application->powerState = HEATPUMP_POWER_STATE_OFF;
        } else {
            unknown = true;
        }
        if (unknown) {
            heatpump_coap_send_error(request, 400, "unknown power state");
        } else {
            heatpump_coap_send_ok(request, 204);
        }
    }

    cJSON_free(root);
}

// change heatpump mode
// CoAP post /heatpump/mode
void heatpump_set_mode(NabtoDeviceCoapRequest* request, void* userData)
{
    struct heatpump_application_state* application = (struct heatpump_application_state*)userData;
    if (!heatpump_coap_check_action(request, "heatpump:SetMode")) {
        return;
    }

    cJSON* root = heatpump_parse_json_request(request);
    if (root == NULL) {
        return;
    }
    char* mode = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(root, "mode"));
    if (mode == NULL) {
        heatpump_coap_send_error(request, 400, "Could not parse json");
    } else {
        bool unknown = false;
        if (strcmp(mode, "cool") == 0) {
            application->mode = HEATPUMP_MODE_COOL;
        } else if (strcmp(mode, "heat") == 0) {
            application->mode = HEATPUMP_MODE_HEAT;
        } else if (strcmp(mode, "circulate") == 0) {
            application->mode = HEATPUMP_MODE_CIRCULATE;
        } else if (strcmp(mode, "dehumidify") == 0) {
            application->mode = HEATPUMP_MODE_DEHUMIDIFY;
        } else {
            unknown = true;
        }

        if (unknown) {
            heatpump_coap_send_error(request, 400, "Unknown mode value");
        } else {
            heatpump_coap_send_ok(request, 204);
        }
    }
    cJSON_free(root);
}

// Set target temperature
// CoAP POST /heatpump/target
void heatpump_set_target(NabtoDeviceCoapRequest* request, void* userData)
{
    struct heatpump_application_state* application = (struct heatpump_application_state*)userData;
    if (!heatpump_coap_check_action(request, "heatpump:SetTarget")) {
        return;
    }

    cJSON* root = heatpump_parse_json_request(request);
    if (root == NULL) {
        return;
    }
    cJSON* temperature = cJSON_GetObjectItemCaseSensitive(root, "target");
    if (!cJSON_IsNumber(temperature)) {
        heatpump_coap_send_error(request, 400, "Could not parse json");
    } else {
        application->target = temperature->valuedouble;
        heatpump_coap_send_ok(request, 204);
    }
    cJSON_free(root);
}

// Get heatpump state
// CoAP GET /heatpump
void heatpump_get(NabtoDeviceCoapRequest* request, void* userData)
{
    struct heatpump_application_state* application = (struct heatpump_application_state*)userData;
    if (!heatpump_coap_check_action(request, "heatpump:GetState")) {
        return;
    }

    cJSON* root = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "power", heatpump_power_state_to_string(application->powerState));
    cJSON_AddStringToObject(root, "mode", heatpump_mode_to_string(application->mode));
    cJSON_AddNumberToObject(root, "roomTemperature", application->roomTemperature);
    cJSON_AddNumberToObject(root, "target", application->target);

    char* encoded = cJSON_PrintUnformatted(root);
    if (encoded == NULL) {
        heatpump_coap_send_error(request, 500, "Internal error");
    } else {
        NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
        nabto_device_coap_response_set_code(response, 200);
        nabto_device_coap_response_set_content_format(response, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_JSON);
        nabto_device_coap_response_set_payload(response, encoded, strlen(encoded));
        nabto_device_coap_response_ready(response);
    }
    cJSON_free(encoded);
    cJSON_free(root);
}


const char* heatpump_power_state_to_string(enum heatpump_power_state powerState)
{
    switch (powerState) {
        case HEATPUMP_POWER_STATE_ON: return "ON";
        case HEATPUMP_POWER_STATE_OFF: return "OFF";
        default: return "UNKNOWN";
    }
}

const char* heatpump_mode_to_string(enum heatpump_mode mode)
{
    switch (mode) {
        case HEATPUMP_MODE_COOL: return "COOL";
        case HEATPUMP_MODE_HEAT: return "HEAT";
        case HEATPUMP_MODE_CIRCULATE: return "CIRCULATE";
        case HEATPUMP_MODE_DEHUMIDIFY: return "DEHUMIDIFY";
        default: return "UNKNOWN";
    }
}
