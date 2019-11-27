#pragma once

#include "abstract_coap_handler.hpp"

#include <iostream>

namespace nabto {
namespace test {

class PostHandler : public AbstractCoapHandler {
 public:
    PostHandler(NabtoDevice* device, NabtoDeviceListener* listener) : AbstractCoapHandler(device, listener) {}
    void handleRequest(NabtoDeviceCoapRequest* request)
    {
        const char* responseData = "helloWorld";
        uint16_t contentFormat;
        nabto_device_coap_request_get_content_format(request, &contentFormat);
        if (contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8) {
            std::cout << "Received CoAP POST request with invalid content format" << std::endl;
            nabto_device_coap_error_response(request, 400, "Invalid content format");
            nabto_device_coap_request_free(request);
        } else {
            char* payload;
            size_t payloadLength;
            nabto_device_coap_request_get_payload(request, (void**)&payload, &payloadLength);
            std::cout << "Received CoAP POST request with a " << payloadLength << " byte payload" << std::endl;
            nabto_device_coap_response_set_code(request, 205);
            nabto_device_coap_response_set_payload(request, responseData, strlen(responseData));
            nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);
            nabto_device_coap_response_ready(request);
            nabto_device_coap_request_free(request);
        }
    }
};


} } // namespace
