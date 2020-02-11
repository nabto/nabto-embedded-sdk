
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
