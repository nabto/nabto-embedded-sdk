#include <boost/test/unit_test.hpp>

#include <test_platform.hpp>

#ifdef HAVE_EPOLL
#include <test_platform_epoll.hpp>
#endif

#ifdef HAVE_LIBEVENT
#include <test_platform_libevent.hpp>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <test_platform_select_unix.hpp>
#endif

#include <platform/np_platform.h>

#include <util/io_service.hpp>
#include <util/udp_echo_server.hpp>
#include <lib/span.hpp>

#include <boost/asio.hpp>

namespace nabto {
namespace test {

class UdpEchoClientTest {
 public:
    UdpEchoClientTest(TestPlatform& tp)
        : tp_(tp), pl_(tp.getPlatform())
    {
    }

    ~UdpEchoClientTest()
    {
    }

    void start(uint16_t port) {
        tp_.init();

        BOOST_TEST(pl_->udp.create(pl_, &socket_) == NABTO_EC_OK);

        uint8_t addr[] = { 0x7F, 0x00, 0x00, 0x01 };

        for (size_t i = 0; i < data_.size(); i++) {
            data_[i] = (uint8_t)i;
        }

        ep_.ip.type = NABTO_IPV4;
        memcpy(ep_.ip.ip.v6, addr, 4);
        ep_.port = port;

        pl_->udp.async_bind_port(socket_, 0, &UdpEchoClientTest::created, this);

        tp_.run();
    }

    static void created(const np_error_code ec, void* data)
    {
        BOOST_TEST(ec == NABTO_EC_OK);
        UdpEchoClientTest* client = (UdpEchoClientTest*)data;
        client->startSend();
    }

    void startSend()
    {

        pl_->udp.async_send_to(socket_, ep_, data_.data(), data_.size(), &UdpEchoClientTest::sent, this);
    }

    static void sent(np_error_code ec, void* data)
    {
        UdpEchoClientTest* client = (UdpEchoClientTest*)data;
        BOOST_TEST(ec == NABTO_EC_OK, np_error_code_to_string(ec));
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
        tp_.stop();
    }

 private:
    nabto::test::TestPlatform& tp_;
    struct np_platform* pl_;
    struct np_udp_endpoint ep_;
    np_udp_socket* socket_;
    std::array<uint8_t, 42> data_;
    std::vector<uint8_t> recvBuffer_;

};

} } // namespace

BOOST_AUTO_TEST_SUITE(udp)

#ifdef HAVE_EPOLL

BOOST_AUTO_TEST_CASE(echo_epoll, * boost::unit_test::timeout(120))
{
    auto ioService = nabto::IoService::create("test");
    auto udpServer = nabto::test::UdpEchoServer::create(ioService->getIoService());

    nabto::test::TestPlatformEpoll epollPlatform;
    nabto::test::UdpEchoClientTest client(epollPlatform);
    client.start(udpServer->getPort());

    BOOST_TEST(udpServer->getPacketCount() > (uint64_t)0);
    udpServer->stop();
}

#endif

#ifdef HAVE_LIBEVENT

BOOST_AUTO_TEST_CASE(echo_libevent, * boost::unit_test::timeout(120))
{
    auto ioService = nabto::IoService::create("test");
    auto udpServer = nabto::test::UdpEchoServer::create(ioService->getIoService());

    nabto::test::TestPlatformLibevent p;
    nabto::test::UdpEchoClientTest client(p);
    client.start(udpServer->getPort());

    BOOST_TEST(udpServer->getPacketCount() > (uint64_t)0);
    udpServer->stop();
}

#endif

BOOST_AUTO_TEST_CASE(echo_select_unix, * boost::unit_test::timeout(120))
{
    auto ioService = nabto::IoService::create("test");
    auto udpServer = nabto::test::UdpEchoServer::create(ioService->getIoService());

    nabto::test::TestPlatformSelectUnix platform;
    nabto::test::UdpEchoClientTest client(platform);
    client.start(udpServer->getPort());

    BOOST_TEST(udpServer->getPacketCount() > (uint64_t)0);
    udpServer->stop();
}

BOOST_AUTO_TEST_SUITE_END()
