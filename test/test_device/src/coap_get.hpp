#pragma once

#include "abstract_coap_handler.hpp"

#include <iostream>

namespace nabto {
namespace test {

class GetHandler : public AbstractCoapHandler {
 public:
    GetHandler(NabtoDevice* device, NabtoDeviceListener* listener) : AbstractCoapHandler(device, listener) {}
    void handleRequest(NabtoDeviceCoapRequest* request)
    {
        NabtoDeviceConnectionRef connectionId = nabto_device_coap_request_get_connection_ref(request);
        std::cout << "Received CoAP GET request, connectionId: " << connectionId << std::endl;
        const char* responseData = "helloWorld";
        nabto_device_coap_response_set_code(request, 205);
        nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);
        nabto_device_coap_response_set_payload(request, responseData, strlen(responseData));
        nabto_device_coap_response_ready(request);
        nabto_device_coap_request_free(request);
    }
};

} } // namespace
