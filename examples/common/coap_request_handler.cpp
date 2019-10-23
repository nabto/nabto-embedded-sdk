#include "coap_request_handler.hpp"

namespace nabto {
namespace common {

CoapRequestHandler::CoapRequestHandler(void* application, NabtoDevice* device, NabtoDeviceCoapMethod method, const char** pathSegments, CoapHandler handler)
    : application_(application), handler_(handler)
{
    nabto_device_coap_listener_new(device, method, pathSegments, &listener_);
    startListen();
}

void CoapRequestHandler::startListen()
{
    NabtoDeviceError ec = nabto_device_listener_new_coap_request(listener_, &future_, &request_);
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_listener_free(listener_);
        return;
    }
    nabto_device_future_set_callback(future_, CoapRequestHandler::requestCallback, this);
}

} } // namespace
