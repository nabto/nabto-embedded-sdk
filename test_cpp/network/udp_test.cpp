#include <boost/test/unit_test.hpp>

#include <test_platform/test_platform.h>

#include <util/io_service.hpp>
#include <lib/span.hpp>

#include <boost/asio.hpp>


/**
 * Plan:
 *  Create echo udp server.
 */

namespace nabto {
namespace test {

class UdpEchoServer : public std::enable_shared_from_this<UdpEchoServer> {
 public:
    UdpEchoServer(boost::asio::io_context& io)
        : io_(io), socket_(io)
    {

    }

    static std::shared_ptr<UdpEchoServer> create(boost::asio::io_context& io)
    {
        auto ptr = std::make_shared<UdpEchoServer>(io);
        ptr->init();
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
                self->startRecv();
            });
    }

 private:
    boost::asio::io_context& io_;
    boost::asio::ip::udp::socket socket_;
    std::array<uint8_t, 1500> recvBuffer_;
    boost::asio::ip::udp::endpoint recvEp_;
    std::atomic<uint64_t> packetCount_ = { 0 };
};

class UdpEchoClientTest {
 public:
    UdpEchoClientTest() {

    }
    ~UdpEchoClientTest() {

    }
    void start(uint16_t port) {
        test_platform_init(&tp_);

        pl_ = &tp_.pl;
        BOOST_TEST(pl_->udp.create(pl_, &socket_) == NABTO_EC_OK);

        uint8_t addr[] = { 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x01 };

        for (size_t i = 0; i < data_.size(); i++) {
            data_[i] = (uint8_t)i;
        }

        sendCtx_.sock = socket_;
        sendCtx_.ep.ip.type = NABTO_IPV6;
        memcpy(sendCtx_.ep.ip.v6.addr, addr, 16);
        sendCtx_.ep.port = port;
        sendCtx_.buffer = data_.data();
        sendCtx_.bufferSize = data_.size();
        sendCtx_.cb =  &UdpEchoClientTest::sent;
        sendCtx_.cbData = this;

        pl_->udp.async_bind(socket_, &UdpEchoClientTest::created, this);

        test_platform_run(&tp_);
    }

    static void created(const np_error_code ec, void* data)
    {
        BOOST_TEST(ec == NABTO_EC_OK);
        UdpEchoClientTest* client = (UdpEchoClientTest*)data;
        client->startSend();
    }

    void startSend()
    {

        pl_->udp.async_send_to(&sendCtx_);
    }

    static void sent(np_error_code ec, void* data)
    {
        UdpEchoClientTest* client = (UdpEchoClientTest*)data;
        BOOST_TEST(ec == NABTO_EC_OK);
        client->startRecv();
    }

    void startRecv()
    {
        pl_->udp.async_recv_from(socket_, &UdpEchoClientTest::received, this);
    }

    static void received(np_error_code ec, struct np_udp_endpoint ep, uint8_t* buffer, uint16_t bufferSize, void* data)
    {
        UdpEchoClientTest* client = (UdpEchoClientTest*)data;
        BOOST_TEST(ec == NABTO_EC_OK);
        auto sentData = lib::span<const uint8_t>(client->data_.data(), client->data_.size());
        auto receivedData = lib::span<const uint8_t>(buffer, bufferSize);
        BOOST_TEST(sentData == receivedData);
        client->end();
    }

    void end() {
        pl_->udp.destroy(socket_);
        test_platform_stop(&tp_);
    }

 private:
    struct test_platform tp_;
    struct np_platform* pl_;
    struct np_udp_send_context sendCtx_;
    np_udp_socket* socket_;
    std::array<uint8_t, 42> data_;
    std::vector<uint8_t> recvBuffer_;

};

} } // namespace


BOOST_AUTO_TEST_SUITE(udp)

BOOST_AUTO_TEST_CASE(echo)
{
    auto ioService = nabto::IoService::create("test");
    auto udpServer = nabto::test::UdpEchoServer::create(ioService->getIoService());

    nabto::test::UdpEchoClientTest client;
    client.start(udpServer->getPort());

    BOOST_TEST(udpServer->getPacketCount() > (uint64_t)0);
    udpServer->stop();
}

BOOST_AUTO_TEST_SUITE_END()
