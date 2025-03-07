#include "nm_tcp_tunnel.h"
#include "nm_tcp_tunnel_coap.h"

#include <core/nc_coap_server.h>
#include <core/nc_coap.h>
#include <platform/np_logging.h>
#include <platform/np_allocator.h>

#include <tinycbor/cbor.h>


#define LOG NABTO_LOG_MODULE_TUNNEL

static void list_services(struct nc_coap_server_request* request, void* data);
static void get_service(struct nc_coap_server_request* request, void* data);
static void get_connect(struct nc_coap_server_request* request, void* data);
static void list_services_iam(bool allow, void* userData1, void* userData2, void* userData3);
static void get_service_iam(bool allow, void* userData1, void* userData2, void* userData3);

static void get_service_action(struct nc_coap_server_request* request, struct nm_tcp_tunnels* tunnels, const char* action);

np_error_code nm_tcp_tunnel_coap_init(struct nm_tcp_tunnels* tunnels, struct nc_coap_server_context* server)
{
    nabto_coap_error err;

    err = nc_coap_server_add_resource(server, NABTO_COAP_METHOD_GET,
                                         (const char*[]){"tcp-tunnels", "services", NULL},
                                         list_services, tunnels, &tunnels->coapListServices);
    if (err != NABTO_COAP_ERROR_OK) {
        nm_tcp_tunnel_coap_deinit(tunnels);
        return nc_coap_error_to_core(err);
    }
    err = nc_coap_server_add_resource(server, NABTO_COAP_METHOD_GET,
                                         (const char*[]){"tcp-tunnels", "services", "{id}", NULL},
                                         get_service, tunnels, &tunnels->coapGetService);
    if (err != NABTO_COAP_ERROR_OK) {
        nm_tcp_tunnel_coap_deinit(tunnels);
        return nc_coap_error_to_core(err);
    }
    err = nc_coap_server_add_resource(server, NABTO_COAP_METHOD_GET,
                                         (const char*[]){"tcp-tunnels", "connect", "{id}", NULL},
                                         get_connect, tunnels, &tunnels->coapGetConnect);
    if (err != NABTO_COAP_ERROR_OK) {
        nm_tcp_tunnel_coap_deinit(tunnels);
        return nc_coap_error_to_core(err);
    }

    return NABTO_EC_OK;
}

void nm_tcp_tunnel_coap_deinit(struct nm_tcp_tunnels* tunnels)
{
    if (tunnels->coapListServices) {
        nc_coap_server_remove_resource(tunnels->coapListServices);
        tunnels->coapListServices = NULL;
    }
    if (tunnels->coapGetService) {
        nc_coap_server_remove_resource(tunnels->coapGetService);
        tunnels->coapGetService = NULL;
    }
    if (tunnels->coapGetConnect) {
        nc_coap_server_remove_resource(tunnels->coapGetConnect);
        tunnels->coapGetConnect = NULL;
    }
}

/**
 * List Services
 *
 * CoAP GET /tcp_tunnels/services
 */
void list_services(struct nc_coap_server_request* request, void* data)
{
    struct nm_tcp_tunnels* tunnels = data;

    struct np_platform* pl = tunnels->device->pl;

    struct np_authorization_request* authReq = pl->authorization.create_request(pl, nc_coap_server_request_get_connection_ref(request), "TcpTunnel:ListServices");
    if (authReq != NULL) {
        pl->authorization.check_access(authReq, list_services_iam, tunnels, request, NULL);
        return;
    }

    // Could not make the iam request
    pl->authorization.discard_request(authReq);
    nc_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), "Out of resources");
    nc_coap_server_request_free(request);
}

static size_t encode_services_list(struct nm_tcp_tunnels* tunnels, uint8_t* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder array;
    CborError err = cbor_encoder_create_array(&encoder, &array, CborIndefiniteLength);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "Failed to create CBOR array: %d", err);
        return 0;
    }

    struct nm_tcp_tunnel_service* service;
    NN_LLIST_FOREACH(service, &tunnels->services)
    {
        err = cbor_encode_text_stringz(&array, service->id);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to encode service id '%s': %d", service->id, err);
            return 0;
        }
    }
    err = cbor_encoder_close_container(&encoder, &array);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "Failed to close CBOR array: %d", err);
        return 0;
    }

    return cbor_encoder_get_extra_bytes_needed(&encoder);
}

static size_t encode_service(struct nm_tcp_tunnel_service* service, uint8_t* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map, metadata_map;
    CborError err = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "Failed to create CBOR map: %d", err);
        return 0;
    }
    {
        err = cbor_encode_text_stringz(&map, "Id");
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to encode 'Id' key: %d", err);
            return 0;
        }
        err = cbor_encode_text_stringz(&map, service->id);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to encode service id '%s': %d", service->id, err);
            return 0;
        }

        err = cbor_encode_text_stringz(&map, "Type");
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to encode 'Type' key: %d", err);
            return 0;
        }
        err = cbor_encode_text_stringz(&map, service->type);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to encode service type '%s': %d", service->type, err);
            return 0;
        }

        err = cbor_encode_text_stringz(&map, "Host");
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to encode 'Host' key: %d", err);
            return 0;
        }
        err = cbor_encode_text_stringz(&map, np_ip_address_to_string(&service->address));
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to encode host address: %d", err);
            return 0;
        }

        err = cbor_encode_text_stringz(&map, "Port");
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to encode 'Port' key: %d", err);
            return 0;
        }
        err = cbor_encode_uint(&map, service->port);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to encode port: %d", err);
            return 0;
        }

        err = cbor_encode_text_stringz(&map, "StreamPort");
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to encode 'StreamPort' key: %d", err);
            return 0;
        }
        err = cbor_encode_uint(&map, service->streamPort);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to encode stream port: %d", err);
            return 0;
        }

        err = cbor_encode_text_stringz(&map, "Metadata");
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to encode 'Metadata' key: %d", err);
            return 0;
        }
        err = cbor_encoder_create_map(&map, &metadata_map, CborIndefiniteLength);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to create CBOR metadata map: %d", err);
            return 0;
        }
        {
            struct nn_string_map_iterator it;
            NN_STRING_MAP_FOREACH(it, &service->metadata)
            {
                err = cbor_encode_text_stringz(&metadata_map, nn_string_map_key(&it));
                if (err != CborNoError) {
                    NABTO_LOG_ERROR(LOG, "Failed to encode metadata key: %d", err);
                    return 0;
                }
                err = cbor_encode_text_stringz(&metadata_map, nn_string_map_value(&it));
                if (err != CborNoError) {
                    NABTO_LOG_ERROR(LOG, "Failed to encode metadata value: %d", err);
                    return 0;
                }
            }
        }
        err = cbor_encoder_close_container(&map, &metadata_map);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to close metadata map: %d", err);
            return 0;
        }
    }
    err = cbor_encoder_close_container(&encoder, &map);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "Failed to close service map: %d", err);
        return 0;
    }
    return cbor_encoder_get_extra_bytes_needed(&encoder);
}


void list_services_iam(bool allow, void* userData1, void* userData2, void* userData3)
{
    (void)userData3;
    struct nm_tcp_tunnels* tunnels = userData1;
    struct nc_coap_server_request* request = userData2;

    if (!allow) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(4,03)), NULL);
        nc_coap_server_request_free(request);
        return;
    }

    size_t bufferSize = encode_services_list(tunnels, NULL, 0);
    uint8_t* buffer = np_calloc(1, bufferSize);
    if (buffer == NULL) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), NULL);
        nc_coap_server_request_free(request);
        return;
    }

    encode_services_list(tunnels, buffer, bufferSize);

    nc_coap_server_response_set_code(request, (nabto_coap_code)(NABTO_COAP_CODE(2,05)));
    nc_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_coap_error err = nc_coap_server_response_set_payload(request, buffer, bufferSize);
    if (err != NABTO_COAP_ERROR_OK) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), NULL);
    } else {
        nc_coap_server_response_ready(request);
    }
    nc_coap_server_request_free(request);
    np_free(buffer);
}

void get_service(struct nc_coap_server_request* request, void* data)
{
    struct nm_tcp_tunnels* tunnels = data;
    get_service_action(request, tunnels, "TcpTunnel:GetService");
}

void get_connect(struct nc_coap_server_request* request, void* data)
{
    struct nm_tcp_tunnels* tunnels = data;
    get_service_action(request, tunnels, "TcpTunnel:Connect");
}

void get_service_action(struct nc_coap_server_request* request, struct nm_tcp_tunnels* tunnels, const char* action)
{
    struct nm_tcp_tunnel_service* service = nm_tcp_tunnels_find_service(tunnels, nc_coap_server_request_get_parameter(request, "id"));
    if (service == NULL) {
        // OOM impossible with NULL message
        nc_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(4,04)), NULL);
        nc_coap_server_request_free(request);
        return;
    }

    struct np_platform* pl = tunnels->device->pl;
    struct np_authorization_request* authReq = pl->authorization.create_request(pl, nc_coap_server_request_get_connection_ref(request), action);
    if (authReq &&
        pl->authorization.add_string_attribute(authReq, "TcpTunnel:ServiceId", service->id) == NABTO_EC_OK &&
        pl->authorization.add_string_attribute(authReq, "TcpTunnel:ServiceType", service->type) == NABTO_EC_OK)
    {
        pl->authorization.check_access(authReq, get_service_iam, tunnels, request, NULL);
        return;
    }

    // Could not make the iam request
    pl->authorization.discard_request(authReq);
    nc_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), NULL);
    nc_coap_server_request_free(request);
}

void get_service_iam(bool allow, void* userData1, void* userData2, void* userData3)
{
    (void)userData3;
    struct nm_tcp_tunnels* tunnels = userData1;
    struct nc_coap_server_request* request = userData2;

    if (!allow) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(4,03)), NULL);
        nc_coap_server_request_free(request);
        return;
    }

    struct nm_tcp_tunnel_service* service = nm_tcp_tunnels_find_service(tunnels, nc_coap_server_request_get_parameter(request, "id"));
    if (service == NULL) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(4,04)), NULL);
        nc_coap_server_request_free(request);
        return;
    }

    size_t bufferSize = encode_service(service, NULL, 0);
    uint8_t* buffer = np_calloc(1, bufferSize);
    if (buffer == NULL) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), NULL);
        nc_coap_server_request_free(request);
        return;
    }

    encode_service(service, buffer, bufferSize);

    nc_coap_server_response_set_code(request, (nabto_coap_code)(NABTO_COAP_CODE(2,05)));
    nc_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_coap_error err = nc_coap_server_response_set_payload(request, buffer, bufferSize);
    if (err != NABTO_COAP_ERROR_OK) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), NULL);
    } else {
        nc_coap_server_response_ready(request);
    }
    nc_coap_server_request_free(request);
    np_free(buffer);
}
