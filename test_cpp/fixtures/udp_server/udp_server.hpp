#pragma once

/**
 * The udp server is a udp instance which listens on several ports and
 * sends traffic to users of the server.
 *
 * The server has a blacklist/whitelist and ratelimit system
 */

#include <cstdint>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/io_context.hpp>

#include <util/span.hpp>

#include <unordered_set>
#include <unordered_map>

namespace std {

template <> struct hash<boost::asio::ip::address>
{
    size_t operator()(const boost::asio::ip::address & addr) const
    {
        std::string s = addr.to_string();
        std::hash<std::string> hash_fn;
        return hash_fn(s);
    }
};

template <> struct hash<boost::asio::ip::udp::endpoint>
{
    size_t operator()(const boost::asio::ip::udp::endpoint & ep) const
    {
        std::hash<boost::asio::ip::address> hash_fn1;
        std::hash<uint16_t> hash_fn2;
        return hash_fn1(ep.address()) + hash_fn2(ep.port());
    }
};



}

namespace nabto {

class UdpServer {
 public:
    UdpServer(boost::asio::io_context& ioContext);
    UdpServer(boost::asio::io_context& ioContext, std::string ip);


    boost::system::error_code open(uint16_t port, boost::system::error_code& ec);

    uint16_t port();

    typedef std::function<void (const boost::system::error_code& ec, std::size_t transferred)> recvCallback;
    typedef std::function<void (const boost::system::error_code& ec)> sentCallback;

    void asyncReceive(lib::span<uint8_t> buffer, boost::asio::ip::udp::endpoint& ep, recvCallback cb);
    void asyncSend(lib::span<const uint8_t> buffer, boost::asio::ip::udp::endpoint ep, sentCallback cb);

    bool checkIncomingPacket(const boost::asio::ip::udp::endpoint& ep);

    void close() {
        boost::system::error_code ec;
        socket_.close(ec);
    }
 private:
    //boost::asio::io_context& ioContext_;
    boost::asio::ip::address address_;
    boost::asio::ip::udp::socket socket_;
    std::unordered_set<boost::asio::ip::udp::endpoint> whiteList_;
    std::unordered_map<boost::asio::ip::udp::endpoint, int> epPacketCounter_;
};

} // namespace
