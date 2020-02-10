#pragma once

#include <nabto/nabto_device.h>

#include <cbor.h>
#include <future>

namespace nabto {
namespace examples {
namespace common {

class AbstractRequestHandler {
 public:

    /**
     * Override the implementation of this function to handle a new
     * request type.
     */
    virtual void handleRequest(NabtoDeviceCoapRequest* request) = 0;

    AbstractRequestHandler(NabtoDevice* device)
        : device_(device), listener_(nabto_device_listener_new(device)), future_(nabto_device_future_new(device))
    {
    }

    virtual ~AbstractRequestHandler()
    {
        stop();
        nabto_device_future_free(future_);
        nabto_device_listener_free(listener_);
    }

    bool init(NabtoDeviceCoapMethod method, const std::vector<std::string>& segments)
    {
        std::vector<const char*> paths;

        for (auto& s : segments) {
            paths.push_back(s.c_str());
        }
        paths.push_back(NULL);

        if (nabto_device_coap_init_listener(device_, listener_, method, paths.data()) != NABTO_DEVICE_EC_OK) {
            return false;
        }

        startListen();
        return true;
    }
    void startListen()
    {
        nabto_device_listener_new_coap_request(listener_, future_, &request_);
        nabto_device_future_set_callback(future_, AbstractRequestHandler::requestCallback, this);
    }

    static void requestCallback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        AbstractRequestHandler* self = static_cast<AbstractRequestHandler*>(userData);
        if (ec == NABTO_DEVICE_EC_OK) {
            self->handleRequest(self->request_);
            self->startListen();
        } else {
            self->promise_.set_value();
        }
    }

    // utility function
    bool initCborParser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue)
    {
        uint16_t contentFormat;
        NabtoDeviceError ec;
        ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
        if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
            nabto_device_coap_error_response(request, 400, "Invalid Content Format");
            nabto_device_coap_request_free(request);
            return false;
        }
        void* payload;
        size_t payloadSize;
        if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
            nabto_device_coap_error_response(request, 400, "Missing payload");
            nabto_device_coap_request_free(request);
            return false;
        }
        cbor_parser_init((const uint8_t*)payload, payloadSize, 0, parser, cborValue);
        return true;
    }

    NabtoDevice* getDevice() {
        return device_;
    }
 protected:
    void stop()
    {
        std::future<void> future = promise_.get_future();
        nabto_device_listener_stop(listener_);

        // wait for the callback to be resolved.
        future.get();
    }
    std::promise<void> promise_;
    NabtoDevice* device_;
    NabtoDeviceListener* listener_;
    NabtoDeviceFuture* future_;
    NabtoDeviceCoapRequest* request_;
};

} } } // namespace
