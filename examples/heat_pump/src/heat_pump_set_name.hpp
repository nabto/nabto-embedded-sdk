#pragma once

#include <examples/common/abstract_request_handler.hpp>

namespace nabto {
namespace examples {
namespace heat_pump {

class HeatPumpSetName : public common::AbstractRequestHandler {
 public:
    HeatPumpSetName(HeatPump& heatPump, NabtoDevice* device)
        : common::AbstractRequestHandler(device), heatPump_(heatPump)
    {
    }

    static std::unique_ptr<HeatPumpSetName> create(HeatPump& heatPump, NabtoDevice* device)
    {
        auto handler = std::make_unique<HeatPumpSetName>(heatPump, device);
        handler->init(NABTO_DEVICE_COAP_POST, {"heat-pump", "name"});
        return handler;
    }

    virtual void handleRequest(NabtoDeviceCoapRequest* request)
    {
        if (!heatPump_.checkAccess(request, "HeatPump:Set")) {
            return;
        }

        CborParser parser;
        CborValue value;
        if (!initCborParser(request, &parser, &value)) {
            return;
        }

        if (!cbor_value_is_text_string(&value)) {
            nabto_device_coap_error_response(request, 400, "Bad request");
            nabto_device_coap_request_free(request);
            return;
        }

        size_t stringLength = 0;
        cbor_value_calculate_string_length(&value, &stringLength);

        if (stringLength > 64) {
            nabto_device_coap_error_response(request, 400, "Bad request");
            nabto_device_coap_request_free(request);
            return;
        }

        char buffer[65];
        memset(buffer, 0, 65);
        stringLength = 64;
        cbor_value_copy_text_string(&value, buffer, &stringLength, NULL);
        heatPump_.setName(std::string(buffer));

        nabto_device_coap_response_set_code(request, 204);
        nabto_device_coap_response_ready(request);
        nabto_device_coap_request_free(request);
    }
 private:
    HeatPump& heatPump_;
};

} } } // namespace
