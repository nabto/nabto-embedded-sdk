#include "coap_request_handler.hpp"

namespace nabto {
namespace common {

CoapRequestHandler::CoapRequestHandler(void* application, NabtoDevice* device, NabtoDeviceCoapMethod method, const char** pathSegments, CoapHandler handler)
    : application_(application), handler_(handler)
{
    future_ = nabto_device_future_new(device);
    nabto_device_coap_listener_new(device, method, pathSegments, &listener_);
    if (!future_) {
        return;
    }
    if (!listener_) {
        return;
    }
    startListen();
}

void CoapRequestHandler::startListen()
{
    nabto_device_listener_new_coap_request(listener_, future_, &request_);
    nabto_device_future_set_callback(future_, CoapRequestHandler::requestCallback, this);
}

} } // namespace
