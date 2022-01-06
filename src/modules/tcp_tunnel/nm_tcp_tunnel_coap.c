#include "nm_tcp_tunnel.h"
#include "nm_tcp_tunnel_coap.h"

#include <core/nc_coap_server.h>
#include <core/nc_coap.h>
#include <platform/np_logging.h>
#include <platform/np_allocator.h>

#include <cbor.h>


#define LOG NABTO_LOG_MODULE_TUNNEL

static void list_services(struct nabto_coap_server_request* request, void* data);
static void get_service(struct nabto_coap_server_request* request, void* data);
static void get_connect(struct nabto_coap_server_request* request, void* data);
static void list_services_iam(bool allow, void* userData1, void* userData2, void* userData3);
static void get_service_iam(bool allow, void* userData1, void* userData2, void* userData3);

static void get_service_action(struct nabto_coap_server_request* request, struct nm_tcp_tunnels* tunnels, const char* action);

np_error_code nm_tcp_tunnel_coap_init(struct nm_tcp_tunnels* tunnels, struct nc_coap_server_context* server)
{
    nabto_coap_error err;

    err = nabto_coap_server_add_resource(&server->server, NABTO_COAP_CODE_GET,
                                         (const char*[]){"tcp-tunnels", "services", NULL},
                                         list_services, tunnels, &tunnels->coapListServices);
    if (err != NABTO_COAP_ERROR_OK) {
        nm_tcp_tunnel_coap_deinit(tunnels);
        return nc_coap_error_to_core(err);
    }
    err = nabto_coap_server_add_resource(&server->server, NABTO_COAP_CODE_GET,
                                         (const char*[]){"tcp-tunnels", "services", "{id}", NULL},
                                         get_service, tunnels, &tunnels->coapGetService);
    if (err != NABTO_COAP_ERROR_OK) {
        nm_tcp_tunnel_coap_deinit(tunnels);
        return nc_coap_error_to_core(err);
    }
    err = nabto_coap_server_add_resource(&server->server, NABTO_COAP_CODE_GET,
                                         (const char*[]){"tcp-tunnels", "connect", "{id}", NULL},
                                         get_connect, tunnels, &tunnels->coapGetService);
    if (err != NABTO_COAP_ERROR_OK) {
        nm_tcp_tunnel_coap_deinit(tunnels);
        return nc_coap_error_to_core(err);
    }
    return NABTO_EC_OK;
}

void nm_tcp_tunnel_coap_deinit(struct nm_tcp_tunnels* tunnels)
{
    if (tunnels->coapListServices) {
        nabto_coap_server_remove_resource(tunnels->coapListServices);
        tunnels->coapListServices = NULL;
    }
    if (tunnels->coapGetService) {
        nabto_coap_server_remove_resource(tunnels->coapGetService);
        tunnels->coapGetService = NULL;
    }
}

/**
 * List Services
 *
 * CoAP GET /tcp_tunnels/services
 */
void list_services(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcp_tunnels* tunnels = data;

    struct np_platform* pl = tunnels->device->pl;
    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    struct np_authorization_request* authReq = pl->authorization.create_request(pl, connection->connectionRef, "TcpTunnel:ListServices");
    if (authReq != NULL) {
        pl->authorization.check_access(authReq, list_services_iam, tunnels, request, NULL);
        return;
    }

    // Could not make the iam request
    pl->authorization.discard_request(authReq);
    nabto_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), "Out of resources");
    nabto_coap_server_request_free(request);
}

static size_t encode_services_list(struct nm_tcp_tunnels* tunnels, uint8_t* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder array;
    cbor_encoder_create_array(&encoder, &array, CborIndefiniteLength);

    struct nm_tcp_tunnel_service* service;
    NN_LLIST_FOREACH(service, &tunnels->services)
    {
        cbor_encode_text_stringz(&array, service->id);
    }
    cbor_encoder_close_container(&encoder, &array);

    return cbor_encoder_get_extra_bytes_needed(&encoder);
}

static size_t encode_service(struct nm_tcp_tunnel_service* service, uint8_t* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    cbor_encode_text_stringz(&map, "Id");
    cbor_encode_text_stringz(&map, service->id);

    cbor_encode_text_stringz(&map, "Type");
    cbor_encode_text_stringz(&map, service->type);

    cbor_encode_text_stringz(&map, "Host");
    cbor_encode_text_stringz(&map, np_ip_address_to_string(&service->address));

    cbor_encode_text_stringz(&map, "Port");
    cbor_encode_uint(&map, service->port);

    cbor_encode_text_stringz(&map, "StreamPort");
    cbor_encode_uint(&map, service->streamPort);

    cbor_encoder_close_container(&encoder, &map);
    return cbor_encoder_get_extra_bytes_needed(&encoder);
}


void list_services_iam(bool allow, void* userData1, void* userData2, void* userData3)
{
    (void)userData3;
    struct nm_tcp_tunnels* tunnels = userData1;
    struct nabto_coap_server_request* request = userData2;

    if (!allow) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(4,03)), NULL);
        nabto_coap_server_request_free(request);
        return;
    }

    size_t bufferSize = encode_services_list(tunnels, NULL, 0);
    uint8_t* buffer = np_calloc(1, bufferSize);
    if (buffer == NULL) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), NULL);
        nabto_coap_server_request_free(request);
        return;
    }

    encode_services_list(tunnels, buffer, bufferSize);

    nabto_coap_server_response_set_code(request, (nabto_coap_code)(NABTO_COAP_CODE(2,05)));
    nabto_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_coap_error err = nabto_coap_server_response_set_payload(request, buffer, bufferSize);
    if (err != NABTO_COAP_ERROR_OK) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), NULL);
    } else {
        nabto_coap_server_response_ready(request);
    }
    nabto_coap_server_request_free(request);
    np_free(buffer);
}

void get_service(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcp_tunnels* tunnels = data;
    get_service_action(request, tunnels, "TcpTunnel:GetService");
}

void get_connect(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcp_tunnels* tunnels = data;
    get_service_action(request, tunnels, "TcpTunnel:Connect");
}

void get_service_action(struct nabto_coap_server_request* request, struct nm_tcp_tunnels* tunnels, const char* action)
{
    struct nm_tcp_tunnel_service* service = nm_tcp_tunnels_find_service(tunnels, nabto_coap_server_request_get_parameter(request, "id"));
    if (service == NULL) {
        // OOM impossible with NULL message
        nabto_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(4,04)), NULL);
        nabto_coap_server_request_free(request);
        return;
    }

    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    struct np_platform* pl = tunnels->device->pl;
    struct np_authorization_request* authReq = pl->authorization.create_request(pl, connection->connectionRef, action);
    if (authReq &&
        pl->authorization.add_string_attribute(authReq, "TcpTunnel:ServiceId", service->id) == NABTO_EC_OK &&
        pl->authorization.add_string_attribute(authReq, "TcpTunnel:ServiceType", service->type) == NABTO_EC_OK)
    {
        pl->authorization.check_access(authReq, get_service_iam, tunnels, request, NULL);
        return;
    }

    // Could not make the iam request
    pl->authorization.discard_request(authReq);
    nabto_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), NULL);
    nabto_coap_server_request_free(request);
}

void get_service_iam(bool allow, void* userData1, void* userData2, void* userData3)
{
    (void)userData3;
    struct nm_tcp_tunnels* tunnels = userData1;
    struct nabto_coap_server_request* request = userData2;

    if (!allow) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(4,03)), NULL);
        nabto_coap_server_request_free(request);
        return;
    }

    struct nm_tcp_tunnel_service* service = nm_tcp_tunnels_find_service(tunnels, nabto_coap_server_request_get_parameter(request, "id"));
    if (service == NULL) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(4,04)), NULL);
        nabto_coap_server_request_free(request);
        return;
    }

    size_t bufferSize = encode_service(service, NULL, 0);
    uint8_t* buffer = np_calloc(1, bufferSize);
    if (buffer == NULL) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), NULL);
        nabto_coap_server_request_free(request);
        return;
    }

    encode_service(service, buffer, bufferSize);

    nabto_coap_server_response_set_code(request, (nabto_coap_code)(NABTO_COAP_CODE(2,05)));
    nabto_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_coap_error err = nabto_coap_server_response_set_payload(request, buffer, bufferSize);
    if (err != NABTO_COAP_ERROR_OK) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), NULL);
    } else {
        nabto_coap_server_response_ready(request);
    }
    nabto_coap_server_request_free(request);
    np_free(buffer);
}
