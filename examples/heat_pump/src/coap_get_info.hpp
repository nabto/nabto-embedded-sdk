#pragma once

#include <examples/common/abstract_request_handler.hpp>

namespace nabto {
namespace examples {
namespace heat_pump {

class CoapGetInfo : public common::AbstractRequestHandler {
 public:
    CoapGetInfo(HeatPump& heatPump, NabtoDevice* device)
        : common::AbstractRequestHandler(device), heatPump_(heatPump)
    {
    }

    static std::unique_ptr<CoapGetInfo> create(HeatPump& heatPump, NabtoDevice* device)
    {
        auto handler = std::make_unique<CoapGetInfo>(heatPump, device);
        handler->init(NABTO_DEVICE_COAP_GET, {"info"});
        return std::move(handler);
    }

    virtual void handleRequest(NabtoDeviceCoapRequest* request)
    {
        if (!heatPump_.checkAccess(request, "Info:Get")) {
            return;
        }

        auto d = json::to_cbor(heatPump_.getInfo());

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
