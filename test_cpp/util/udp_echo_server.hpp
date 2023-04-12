#pragma once

#include <nn/log.h>

#include <boost/asio.hpp>

#include <set>

//static const char* LOG_MODULE = "udp_echo_server";

namespace nabto {
namespace test {


class UdpEchoServerImpl : public std::enable_shared_from_this<UdpEchoServerImpl> {
 public:
    UdpEchoServerImpl(boost::asio::io_context& io, struct nn_log* logger, uint16_t port)
        : io_(io), socket_(io), logger_(logger)
    {
    }
    static std::shared_ptr<UdpEchoServerImpl> create(boost::asio::io_context& io, struct nn_log* logger, uint16_t port)
    {
        auto s = std::make_shared<UdpEchoServerImpl>(io, logger, port);
        s->init();
        return s;
    }

    void init() {
        boost::system::error_code ec;
        socket_.open(boost::asio::ip::udp::v4(), ec);
        if (ec) {
            NN_LOG_TRACE(logger_, LOG_MODULE, "cannot open socket %s", ec.message());
        }
        socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
        if (ec) {
            NN_LOG_TRACE(logger_, LOG_MODULE, "cannot bind socket %s", ec.message());
        }
        startRecv();
    }

    void startRecv() {
        if (stopped_) {
            return;
        }
        auto self = shared_from_this();
        socket_.async_receive_from(boost::asio::buffer(recvBuffer_), recvEndpoint_, [self](const boost::system::error_code& ec, std::size_t transferred){
            self->handleSend(ec, transferred);
        });
    }

    void handleSend(const boost::system::error_code& ec, std::size_t transferred) {
        if (stopped_) {
            return;
        }
        if (ec) {
            NN_LOG_TRACE(logger_, LOG_MODULE, "recv failed %s", ec.message());
            startRecv();
        } else {
            auto self = shared_from_this();
            socket_.async_send_to(boost::asio::buffer(recvBuffer_.data(), transferred), recvEndpoint_, [self](const boost::system::error_code& ec, std::size_t transferred){
                if (ec) {
                    NN_LOG_TRACE(self->logger_, LOG_MODULE, "Send to failed %s", ec.message());
                }
                self->startRecv();
            });
        }
    }

    void stop() {
        auto self = shared_from_this();
        io_.post([self](){
                self->stopped_ = true;
                self->socket_.close();
            });
    }

    uint16_t getPort() {
        boost::system::error_code ec;
        boost::asio::ip::udp::endpoint ep = socket_.local_endpoint(ec);
        return ep.port();
    }

 private:
    bool stopped_ = false;
    boost::asio::io_context& io_;
    boost::asio::ip::udp::socket socket_;
    std::array<uint8_t, 1500> recvBuffer_;
    boost::asio::ip::udp::endpoint recvEndpoint_;

    struct nn_log* logger_;
};

class UdpEchoServer {
 public:
    UdpEchoServer(boost::asio::io_context& io, struct nn_log* logger)
    {
        impl_ = UdpEchoServerImpl::create(io, logger, 0);
    }
    UdpEchoServer(boost::asio::io_context& io, struct nn_log* logger, uint16_t port)
    {
        impl_ = UdpEchoServerImpl::create(io, logger, port);
    }
    ~UdpEchoServer()
    {
        impl_->stop();
    }
    uint16_t getPort() {
        return impl_->getPort();
    }
 private:
    std::shared_ptr<UdpEchoServerImpl> impl_;
};

} } // namespace
