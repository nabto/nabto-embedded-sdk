#pragma once

#include <lib/span.hpp>

#include <boost/asio.hpp>

#include <nn/log.h>

#include <iostream>

static const char* LOG = "udp_echo_server";

namespace nabto {
namespace test {

class UdpEchoServer : public std::enable_shared_from_this<UdpEchoServer> {
 public:
    UdpEchoServer(boost::asio::io_context& io, struct nn_log* logger)
        : io_(io), socket_(io), logger_(logger)
    {

    }

    static std::shared_ptr<UdpEchoServer> create(boost::asio::io_context& io)
    {
        auto ptr = std::make_shared<UdpEchoServer>(io, nullptr);
        ptr->init();
        ptr->startRecv();
        return ptr;
    }

    static std::shared_ptr<UdpEchoServer> create(boost::asio::io_context& io, struct nn_log* logger, uint16_t port)
    {
        auto ptr = std::make_shared<UdpEchoServer>(io, logger);
        auto ec = ptr->init(port);
        if (ec) {
            std::cerr << "Failed to start udp echo server " << ec.message() << std::endl;
            return nullptr;
        }
        ptr->startRecv();
        return ptr;
    }

    void stop() {
        boost::system::error_code ec;
        socket_.close(ec);
    }

    void init() {
        boost::system::error_code ec;
        socket_.open(boost::asio::ip::udp::v6(), ec);
        socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), 0), ec);
    }

    boost::system::error_code init(uint16_t port)
    {
        boost::system::error_code ec;
        socket_.open(boost::asio::ip::udp::v6(), ec);
        socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), port), ec);
        return ec;
    }

    uint16_t getPort()
    {
        boost::system::error_code ec;
        boost::asio::ip::udp::endpoint ep = socket_.local_endpoint(ec);
        return ep.port();
    }

    uint64_t getPacketCount()
    {
        return packetCount_;
    }

    void startRecv()
    {
        auto self = shared_from_this();
        socket_.async_receive_from(
            boost::asio::buffer(recvBuffer_.data(), recvBuffer_.size()), recvEp_,
            [self](const boost::system::error_code& ec, std::size_t transferred)
            {
                if (ec) {
                    // incorrectly handles too small recv buffer errors
                    return;
                }
                NN_LOG_TRACE(self->logger_, LOG, "Received UDP packet of size %d from %s", transferred, self->recvEp_.address().to_string().c_str());
                self->packetCount_ += 1;
                self->startSend(transferred);
            });
    }

    void startSend(std::size_t transferred)
    {
        auto self = shared_from_this();
        socket_.async_send_to(
            boost::asio::buffer(recvBuffer_.data(), transferred), recvEp_,
            [self](const boost::system::error_code& ec, std::size_t transferred)
            {
                if (ec) {
                    // Do nothing
                }
                NN_LOG_TRACE(self->logger_, LOG, "Sent UDP packet of size %d to %s", transferred, self->recvEp_.address().to_string().c_str());
                self->startRecv();
            });
    }

 private:
    boost::asio::io_context& io_;
    boost::asio::ip::udp::socket socket_;
    std::array<uint8_t, 1500> recvBuffer_;
    boost::asio::ip::udp::endpoint recvEp_;
    std::atomic<uint64_t> packetCount_ = { 0 };
    struct nn_log* logger_;
};

} } // namespace
