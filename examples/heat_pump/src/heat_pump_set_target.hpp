#pragma once

#include <examples/common/abstract_request_handler.hpp>
#include <cbor.h>
#include <cbor_extra.h>

namespace nabto {
namespace examples {
namespace heat_pump {

class HeatPumpSetTarget : public common::AbstractRequestHandler {
 public:
    HeatPumpSetTarget(HeatPump& heatPump, NabtoDevice* device)
        : common::AbstractRequestHandler(device), heatPump_(heatPump)
    {
    }

    static std::unique_ptr<HeatPumpSetTarget> create(HeatPump& heatPump, NabtoDevice* device)
    {
        auto handler = std::make_unique<HeatPumpSetTarget>(heatPump, device);
        handler->init(NABTO_DEVICE_COAP_POST, {"heat-pump", "target"});
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

        if (!cbor_value_is_floating_point(&value)) {
            nabto_device_coap_error_response(request, 400, "Bad request");
            nabto_device_coap_request_free(request);
            return;
        }

        double target;
        if (cbor_value_get_floating_point(&value, &target) != CborNoError) {
            nabto_device_coap_error_response(request, 400, "Bad request");
            nabto_device_coap_request_free(request);
            return;
        }
        heatPump_.setTarget(target);
        nabto_device_coap_response_set_code(request, 204);
        nabto_device_coap_response_ready(request);
        nabto_device_coap_request_free(request);
    }
 private:
    HeatPump& heatPump_;
};

} } } // namespace
