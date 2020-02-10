#pragma once

#include <examples/common/abstract_request_handler.hpp>

namespace nabto {
namespace examples {
namespace heat_pump {

class HeatPumpSetMode : public common::AbstractRequestHandler {
 public:
    HeatPumpSetMode(HeatPump& heatPump, NabtoDevice* device)
        : common::AbstractRequestHandler(device), heatPump_(heatPump)
    {
    }

    static std::unique_ptr<HeatPumpSetMode> create(HeatPump& heatPump, NabtoDevice* device)
    {
        auto handler = std::make_unique<HeatPumpSetMode>(heatPump, device);
        handler->init(NABTO_DEVICE_COAP_POST, {"heat-pump", "mode"});
        return std::move(handler);
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

        const char* cool = "COOL";
        const char* heat = "HEAT";
        const char* fan = "FAN";
        const char* dry = "DRY";
        bool match;

        if ((cbor_value_text_string_equals(&value, cool, &match) == CborNoError) && match) {
            heatPump_.setMode(HeatPump::Mode::COOL);
        } else if ((cbor_value_text_string_equals(&value, heat, &match) == CborNoError) && match) {
            heatPump_.setMode(HeatPump::Mode::HEAT);
        } else if ((cbor_value_text_string_equals(&value, fan, &match) == CborNoError) && match) {
            heatPump_.setMode(HeatPump::Mode::FAN);
        } else if ((cbor_value_text_string_equals(&value, dry, &match) == CborNoError) && match) {
            heatPump_.setMode(HeatPump::Mode::DRY);
        } else {
            nabto_device_coap_error_response(request, 400, "Bad request");
            nabto_device_coap_request_free(request);
            return;
        }

        nabto_device_coap_response_set_code(request, 204);
        nabto_device_coap_response_ready(request);
        nabto_device_coap_request_free(request);
    }
 private:
    HeatPump& heatPump_;
};

} } } // namespace
