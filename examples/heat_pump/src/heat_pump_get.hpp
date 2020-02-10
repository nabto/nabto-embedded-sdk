#pragma once

#include <examples/common/abstract_request_handler.hpp>

namespace nabto {
namespace examples {
namespace heat_pump {

class HeatPumpGet : public common::AbstractRequestHandler {
 public:
    HeatPumpGet(HeatPump& heatPump, NabtoDevice* device)
        : common::AbstractRequestHandler(device), heatPump_(heatPump)
    {
    }

    static std::unique_ptr<HeatPumpGet> create(HeatPump& heatPump, NabtoDevice* device)
    {
        auto handler = std::make_unique<HeatPumpGet>(heatPump, device);
        handler->init(NABTO_DEVICE_COAP_GET, {"heat-pump"});
        return std::move(handler);
    }

    virtual void handleRequest(NabtoDeviceCoapRequest* request)
    {
        if (!heatPump_.checkAccess(request, "HeatPump:Get")) {
            return;
        }

        auto d = json::to_cbor(heatPump_.getState());

        nabto_device_coap_response_set_code(request, 205);
        nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        NabtoDeviceError ec = nabto_device_coap_response_set_payload(request, d.data(), d.size());
        if (ec != NABTO_DEVICE_EC_OK) {
            nabto_device_coap_error_response(request, 500, "Insufficient resources");
        } else {
            nabto_device_coap_response_ready(request);
        }
        nabto_device_coap_request_free(request);
    }
 private:
    HeatPump& heatPump_;
};

} } } // namespace
