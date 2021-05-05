#include "coap_server.hpp"

#include <algorithm>

namespace nabto {
namespace coap {

class Callbacks {
 public:
    static uint32_t getStamp(void* userData) {
        CoapServer* server = (CoapServer*)userData;
        return server->getStamp();
    }

    static void notifyEvent(void* userData) {
        CoapServer* server = (CoapServer*)userData;
        return server->notifyEvent();
    }
};

void CoapServer::handlePacket(std::shared_ptr<coap::CoapConnection> connection, lib::span<const uint8_t> data)
{
    void* c = connection.get();
    connections_[c] = connection;
    nabto_coap_server_handle_packet(&requests_, c, data.data(), data.size());
    event();
}

void CoapServer::removeConnection(std::shared_ptr<coap::CoapConnection> connection)
{
    void* c = connection.get();
    connections_.erase(c);
    nabto_coap_server_remove_connection(&requests_, c);
    event();
}

std::shared_ptr<CoapServer> CoapServer::create(boost::asio::io_context& io)
{
    auto server = std::make_shared<CoapServer>(io);
    server->init();
    return server;
}

void CoapServer::init()
{
    // init can only fail with oom, assuming this cannot happen in C++
    nabto_coap_server_init(&server_);
    nabto_coap_server_requests_init(&requests_, &server_, &Callbacks::getStamp, &Callbacks::notifyEvent, this);
    setInfiniteStamp();
}

void CoapServer::notifyEvent()
{
    auto self = shared_from_this();
    io_.post([self](){ self->event(); });
}

void CoapServer::event()
{
    enum nabto_coap_server_next_event nextEvent = nabto_coap_server_next_event(&requests_);
    switch (nextEvent) {
        case NABTO_COAP_SERVER_NEXT_EVENT_SEND:
            handleSend();
            return;
        case NABTO_COAP_SERVER_NEXT_EVENT_WAIT:
            handleWait();
            return;
        case NABTO_COAP_SERVER_NEXT_EVENT_NOTHING:
            return;
    }
}

void CoapServer::handleSend()
{
    if (isSending_) {
        // event will be called when we are finished sending and this
        // will trigger a new handleSend if it's still needed.
        return;
    }
    void* connection = nabto_coap_server_get_connection_send(&requests_);
    if (!connection) {
        // this should not happen
        event();
        return;
    }

    std::shared_ptr<coap::CoapConnection> c = connections_[connection];

    if (!c) {
        // never here
        return;
    }

    size_t mtu = c->getMtu();

    uint8_t* end = sendBuffer_.data() + std::min(mtu, sendBuffer_.size());
    uint8_t* ptr = nabto_coap_server_handle_send(&requests_, sendBuffer_.data(), end);

    if (ptr == NULL || ptr < sendBuffer_.data()) {
        // this should not happen
        event();
        return;
    }

    size_t sendSize = ptr - sendBuffer_.data();

    auto self = shared_from_this();
    isSending_ = true;
    c->coapAsyncSend(lib::span<const uint8_t>(sendBuffer_.data(), sendSize), [self](const lib::error_code& /*ec*/){
            self->isSending_ = false;
            self->event();
        });
}


std::shared_ptr<coap::CoapConnection> CoapServer::getConnection(void* connection)
{
    std::shared_ptr<coap::CoapConnection> c = connections_[connection];
    return c;
}


void CoapServer::handleWait()
{
    if (stopped_) {
        return;
    }
    auto self = shared_from_this();
    uint32_t nextStamp;
    nabto_coap_server_get_next_timeout(&requests_, &nextStamp);
    if (nabto_coap_is_stamp_less(nextStamp, currentExpiry_)) {
        currentExpiry_ = nextStamp;
        uint32_t now = nabto_coap_server_stamp_now(&requests_);
        int32_t diff = nabto_coap_stamp_diff(nextStamp, now);
        timer_.expires_from_now(std::chrono::milliseconds(diff));
        timer_.async_wait([self](const boost::system::error_code& ec) {
                if (ec) {
                    return;
                }
                self->handleTimeout();
            });
    }
}

void CoapServer::handleTimeout()
{
    setInfiniteStamp();
    nabto_coap_server_handle_timeout(&requests_);
    event();
}

void CoapServer::setInfiniteStamp()
{
    currentExpiry_ = nabto_coap_server_stamp_now(&requests_);
    currentExpiry_ += (1 << 29);
}

} } // namespace
