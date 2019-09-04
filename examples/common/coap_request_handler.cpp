#include "coap_request_handler.hpp"

namespace nabto {
namespace common {

CoapRequestHandler::CoapRequestHandler(void* application, NabtoDevice* device, NabtoDeviceCoapMethod method, const char** pathSegments, CoapHandler handler)
    : application_(application), handler_(handler)
{
    nabto_device_coap_add_resource(device, method, pathSegments, &resource_);
    startListen();
}

void CoapRequestHandler::startListen()
{
    future_ = nabto_device_coap_resource_listen(resource_, &request_);
    nabto_device_future_set_callback(future_, CoapRequestHandler::requestCallback, this);
}

} } // namespace
