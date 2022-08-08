#if defined(NABTO_DEVICE_ENABLE_PASSWORD_AUTHENTICATION)

#include "nc_spake2.h"
#include "nc_client_connection.h"
#include "nc_device.h"
#include <platform/np_logging.h>
#include <platform/np_allocator.h>



#include <string.h>

#define LOG NABTO_LOG_MODULE_CLIENT_CONNECTION

void newTokenEvent(void* data);

void nc_spake2_init(struct nc_spake2_module* module, struct np_platform* pl)
{
    module->passwordRequestHandler = NULL;
    module->passwordRequestHandlerData = NULL;
    module->spake21 = NULL;
    module->spake22 = NULL;
    module->tokens = NC_SPAKE2_MAX_TOKENS;
    module->pl = pl;
    np_event_queue_create_event(&pl->eq, &newTokenEvent, module, &module->tbEvent);
    module->initialized = true;
}

void nc_spake2_deinit(struct nc_spake2_module* module)
{
    if (module->initialized) {
        np_event_queue_destroy_event(&module->pl->eq, module->tbEvent);
    }
}

void nc_spake2_clear_password_request_callback(struct nc_spake2_module* module)
{
    module->passwordRequestHandler = NULL;
    module->passwordRequestHandlerData = NULL;
}

np_error_code nc_spake2_set_password_request_callback(struct nc_spake2_module* module, nc_spake2_password_request_handler passwordRequestFunction, void* data)
{
    if (module->passwordRequestHandler != NULL) {
        return NABTO_EC_IN_USE;
    }
    module->passwordRequestHandler = passwordRequestFunction;
    module->passwordRequestHandlerData = data;
    return NABTO_EC_OK;
}

struct nc_spake2_password_request* nc_spake2_password_request_new()
{
    struct nc_spake2_password_request* passwordRequest = np_calloc(1, sizeof(struct nc_spake2_password_request));
    if (passwordRequest == NULL) {
        return NULL;
    }
    return passwordRequest;
}

void nc_spake2_password_request_free(struct nc_spake2_password_request* passwordRequest)
{
    if (passwordRequest == NULL) {
        return;
    }
    np_free(passwordRequest->username);
    np_free(passwordRequest->T);
    np_free(passwordRequest);
}

void nc_spake2_password_ready(struct nc_spake2_password_request* req, const char* password)
{

    struct nabto_coap_server_request* coap = req->coapRequest;
    struct nc_client_connection* connection = (struct nc_client_connection*)nabto_coap_server_request_get_connection(coap);

    if (connection == NULL) {
        nabto_coap_server_send_error_response(coap, (nabto_coap_code)NABTO_COAP_CODE(5,00), NULL);
    } else {
        nc_client_connection_get_client_fingerprint(connection, req->clientFingerprint);
        req->pl->spake2.get_fingerprint_from_private_key(connection->device->privateKey, req->deviceFingerprint);

        size_t olen;
        uint8_t buffer[256];
        if (req->pl->spake2.calculate_key(NULL, req, password, buffer, &olen,
                                      connection->spake2Key) == NABTO_EC_OK) {
            connection->hasSpake2Key = true;
            strcpy(connection->username, req->username);
            // respond with S
            nabto_coap_server_response_set_payload(coap, buffer, olen);
            nabto_coap_server_response_set_code_human(coap, 201);
            nabto_coap_server_response_set_content_format(coap, NABTO_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM);
            nabto_coap_server_response_ready(coap);
        } else {
            nabto_coap_server_send_error_response(coap, (nabto_coap_code)NABTO_COAP_CODE(5,00), NULL);
        }


    }

    nabto_coap_server_request_free(coap);
    nc_spake2_password_request_free(req);
}

void newTokenEvent(void* data)
{
    struct nc_spake2_module* module = (struct nc_spake2_module*)data;
    module->tokens++;
    if (module->tokens < NC_SPAKE2_MAX_TOKENS) { // if not at max, add another token later
        np_event_queue_post_timed_event(&module->pl->eq, module->tbEvent, NC_SPAKE2_TOKEN_INTERVAL);
    }
}

void nc_spake2_spend_token(struct nc_spake2_module* module)
{
    if (module->tokens == NC_SPAKE2_MAX_TOKENS) { // if not at max, the event is already scheduled
        np_event_queue_post_timed_event(&module->pl->eq, module->tbEvent, NC_SPAKE2_TOKEN_INTERVAL);
    }
    module->tokens--;
}


#endif
