#pragma once

#include <examples/common/abstract_request_handler.hpp>

namespace nabto {
namespace examples {
namespace heat_pump {

class HeatPumpSetPower : public common::AbstractRequestHandler {
 public:
    HeatPumpSetPower(HeatPump& heatPump, NabtoDevice* device)
        : common::AbstractRequestHandler(device), heatPump_(heatPump)
    {
    }

    static std::unique_ptr<HeatPumpSetPower> create(HeatPump& heatPump, NabtoDevice* device)
    {
        auto handler = std::make_unique<HeatPumpSetPower>(heatPump, device);
        handler->init(NABTO_DEVICE_COAP_POST, {"heat-pump", "power"});
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

        bool powerState;
        if (!cbor_value_is_boolean(&value) || cbor_value_get_boolean(&value, &powerState) != CborNoError) {
            nabto_device_coap_error_response(request, 400, "Invalid request");
            nabto_device_coap_request_free(request);
            return;
        }

        heatPump_.setPower(powerState);
        nabto_device_coap_response_set_code(request, 204);
        nabto_device_coap_response_ready(request);
        nabto_device_coap_request_free(request);
    }
 private:
    HeatPump& heatPump_;
};

} } } // namespace
