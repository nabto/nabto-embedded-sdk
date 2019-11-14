
#include "tcptunnel_coap.hpp"
#include "tcptunnel.hpp"

#include <nabto/nabto_device_experimental.h>

#include "coap_request_handler.hpp"

#include <iostream>

#include <cbor.h>

void tcptunnel_pairing_password(NabtoDeviceCoapRequest* request, void* userData);
void tcptunnel_get_is_paired(NabtoDeviceCoapRequest* request, void* userData);



void tcptunnel_coap_init(NabtoDevice* device, TcpTunnel* tcpTunnel)
{
    const char* postPairingPassword[] = { "pairing", "password", NULL };
    tcpTunnel->coapPostPairingPassword = std::make_unique<nabto::common::CoapRequestHandler>(tcpTunnel, device, NABTO_DEVICE_COAP_POST, postPairingPassword, &tcptunnel_pairing_password);

    const char* getPairingState[] = { "pairing", "is-paired", NULL };
    tcpTunnel->coapGetPairingState = std::make_unique<nabto::common::CoapRequestHandler>(tcpTunnel, device, NABTO_DEVICE_COAP_GET, getPairingState, &tcptunnel_get_is_paired);
}

void tcptunnel_coap_deinit(TcpTunnel* tcpTunnel)
{
    tcpTunnel->coapPostPairingPassword->stopListen();
    tcpTunnel->coapGetPairingState->stopListen();
}

bool tcptunnel_init_cbor_parser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue)
{
    uint16_t contentFormat;
    NabtoDeviceError ec;
    ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        nabto_device_coap_error_response(request, 400, "Invalid Content Format");
        nabto_device_coap_request_free(request);
        return false;
    }
    void* payload;
    size_t payloadSize;
    if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 400, "Missing payload");
        nabto_device_coap_request_free(request);
        return false;
    }
    cbor_parser_init((const uint8_t*)payload, payloadSize, 0, parser, cborValue);
    return true;
}

/**
 * CoAP POST /pairing/password
 *
 * Password based pairing function where the client provides a secret
 * over a secure channel.
 *
 * Request
 * ContentFormat: application/cbor
 * String: Password
 *
 * Response
 *   If denied 403,
 *   Invalid request 400,
 *   Ok: 201
 */

void tcptunnel_pairing_password(NabtoDeviceCoapRequest* request, void* userData)
{
    TcpTunnel* application = (TcpTunnel*)userData;

    CborParser parser;
    CborValue value;
    if (!tcptunnel_init_cbor_parser(request, &parser, &value)) {
        return;
    }

    if (!cbor_value_is_text_string(&value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        nabto_device_coap_request_free(request);
        return;
    }

    bool equal;
    // TODO make random password
    if (cbor_value_text_string_equals(&value, application->getPairingPassword().c_str(), &equal) != CborNoError) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        nabto_device_coap_request_free(request);
        return;
    }

    if (!equal) {
        nabto_device_coap_error_response(request, 403, "Access denied");
        nabto_device_coap_request_free(request);
        return;
    } else {
        NabtoDeviceError ec;
        NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
        char* fingerprint;
        ec = nabto_device_connection_get_client_fingerprint_hex(application->getDevice(), ref, &fingerprint);
        if (ec) {
            nabto_device_coap_error_response(request, 500, "Server error");
            nabto_device_coap_request_free(request);
            return;
        }

        std::string fp(fingerprint);
        nabto_device_string_free(fingerprint);

        ec = nabto_device_iam_users_add_fingerprint(application->getDevice(), "DefaultUser", fp.c_str());
        if (ec) {
            std::cout << "Could not add fingerprint to the default user" << std::endl;
            nabto_device_coap_error_response(request, 500, "Server error");
            nabto_device_coap_request_free(request);
            return;
        }
        std::cout << "Added the fingerprint " << fp << " to the DefaultUser" << std::endl;
        // OK response
        nabto_device_coap_response_set_code(request, 201);
        nabto_device_coap_response_ready(request);
        nabto_device_coap_request_free(request);
    }
}

/**
 * Return 205 if paired, else return 403
 */
void tcptunnel_get_is_paired(NabtoDeviceCoapRequest* request, void* userData)
{
    TcpTunnel* application = (TcpTunnel*)userData;

    NabtoDeviceConnectionRef connectionRef = nabto_device_coap_request_get_connection_ref(request);
    NabtoDeviceError isPaired = nabto_device_iam_check_action(application->getDevice(), connectionRef, "Pairing:IsPaired");
    if (isPaired == NABTO_DEVICE_EC_OK) {
        nabto_device_coap_response_set_code(request, 205);
    } else {
        nabto_device_coap_response_set_code(request, 403);
    }

    nabto_device_coap_response_ready(request);
    nabto_device_coap_request_free(request);
}
