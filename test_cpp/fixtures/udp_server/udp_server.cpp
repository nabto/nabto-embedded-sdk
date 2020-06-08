#include "udp_server.hpp"

#include <boost/asio/ip/v6_only.hpp>

namespace nabto {

UdpServer::UdpServer(boost::asio::io_context& ioContext)
    : //ioContext_(ioContext),
      socket_(ioContext)
{
}

boost::system::error_code UdpServer::open(uint16_t port, boost::system::error_code& ec)
{
    boost::asio::ip::v6_only option(false);
    socket_.set_option(option, ec);

    socket_.open(boost::asio::ip::udp::v6(), ec);
    if (ec) {
        return ec;
    }

    boost::asio::ip::udp::endpoint ep(boost::asio::ip::udp::v6(), port);
    socket_.bind(ep, ec);

    return ec;
}

uint16_t UdpServer::port()
{
    boost::system::error_code ec;
    boost::asio::ip::udp::endpoint ep = socket_.local_endpoint(ec);
    return ep.port();
}

void UdpServer::asyncReceive(lib::span<uint8_t> buffer, boost::asio::ip::udp::endpoint& ep, recvCallback cb)
{
    socket_.async_receive_from(boost::asio::buffer(buffer.data(), buffer.size()), ep, [buffer, cb, &ep, this] (const boost::system::error_code& ec, std::size_t transferred) {
            if (ec) {
                return cb(ec, transferred);
            } else if (checkIncomingPacket(ep)) {
                return cb(ec, transferred);
            } else {
                return asyncReceive(buffer, ep, cb);
            }
        });
}

void UdpServer::asyncSend(lib::span<const uint8_t> buffer, boost::asio::ip::udp::endpoint ep, sentCallback cb)
{
    socket_.async_send_to(boost::asio::buffer(buffer.data(), buffer.size()), ep, [cb](const boost::system::error_code& ec, std::size_t) {
            return cb(ec);
        });
}

bool UdpServer::checkIncomingPacket(const boost::asio::ip::udp::endpoint&)
{
    return true;
}



} // namespace
