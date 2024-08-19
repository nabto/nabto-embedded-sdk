#pragma once

#include <nabto_coap/nabto_coap_server.h>
#include "coap_connection.hpp"

#include <util/span.hpp>
#include <util/error_code.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <set>
#include <map>

namespace nabto {
namespace coap {

class CoapPacketHandler {
 public:
    virtual ~CoapPacketHandler() {};
    virtual void handlePacket(std::shared_ptr<coap::CoapConnection> connection, lib::span<const uint8_t> packet) = 0;
};
class CoapServer : public CoapPacketHandler, public std::enable_shared_from_this<CoapServer> {
 public:
    CoapServer(boost::asio::io_context& io)
        : io_(io), timer_(io)
    {}

    ~CoapServer() {
        nabto_coap_server_requests_destroy(&requests_);
        nabto_coap_server_destroy(&server_);
    };

    static std::shared_ptr<CoapServer> create(boost::asio::io_context& io);

    void init();

    void stop() {
        stopped_ = true;
        timer_.cancel();
        connections_.clear();
    }

    virtual void handlePacket(std::shared_ptr<coap::CoapConnection> connection, lib::span<const uint8_t> packet) override;

    void removeConnection(std::shared_ptr<coap::CoapConnection> connection);

    uint32_t getStamp()
    {
        uint64_t milliseconds_since_epoch =
            std::chrono::duration_cast<std::chrono::milliseconds>
            (std::chrono::steady_clock::now().time_since_epoch()).count();
        return (uint32_t)milliseconds_since_epoch;
    }

    nabto_coap_error addResource(nabto_coap_code method, const char** segments, nabto_coap_server_resource_handler handler, void* userData) {
        // TODO: add ability to remove resource instead of throwing pointer away
        struct nabto_coap_server_resource* resource;
        return nabto_coap_server_add_resource(&server_, method, segments, handler, userData, &resource);
    }

    nabto_coap_error addResource(nabto_coap_code method, const char** segments, nabto_coap_server_resource_handler handler, void* userData, struct nabto_coap_server_resource** resource) {
        return nabto_coap_server_add_resource(&server_, method, segments, handler, userData, resource);
    }

    void removeResource(struct nabto_coap_server_resource* resource) {
        return nabto_coap_server_remove_resource(resource);
    }


    void notifyEvent();

    void setAckTimeout(uint32_t millis) {
        server_.ackTimeout = millis;
    }

    std::shared_ptr<coap::CoapConnection> getConnection(void* connection);

 private:

    void event();
    void handleSend();
    void handleWait();
    void setInfiniteStamp();
    void handleTimeout();

    boost::asio::io_context& io_;
    boost::asio::steady_timer timer_;
    struct nabto_coap_server server_;
    struct nabto_coap_server_requests requests_;

    std::array<uint8_t, 1500> sendBuffer_;
    uint32_t currentExpiry_;
    bool isSending_ = false;

    std::map<void*, std::shared_ptr<coap::CoapConnection> > connections_;
    bool stopped_ = false;

};


} } // namespace
