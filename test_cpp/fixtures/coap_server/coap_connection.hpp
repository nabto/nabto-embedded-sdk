#pragma once

#include <util/span.hpp>
#include <util/error_code.hpp>

#include <functional>

namespace nabto {
namespace coap {

/**
 * Coap connection interface
 */
class CoapConnection {
 public:
    virtual ~CoapConnection() {}
    typedef std::function<void (const lib::error_code& ec)> SendHandler;
    virtual void coapAsyncSend(lib::span<const uint8_t> packet, SendHandler handler) = 0;

    virtual uint16_t getMtu() = 0;
};

} } // namespace
