#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <test_platform.hpp>

#include <platform/np_platform.h>
#include <platform/np_completion_event.h>
#include <platform/np_udp_wrapper.h>

#include <util/io_service.hpp>
#include <fixtures/udp_echo_server.hpp>
#include <util/span.hpp>

#include <boost/asio.hpp>

namespace nabto {
namespace test {

class UdpEchoClientTest {
 public:
    UdpEchoClientTest(TestPlatform& tp)
        : tp_(tp), pl_(tp.getPlatform()), eq_(pl_->eq)
    {
        np_completion_event_init(&eq_, &completionEvent_, NULL, NULL);
    }

    ~UdpEchoClientTest()
    {
        np_completion_event_deinit(&completionEvent_);
    }

    void start(uint16_t port) {
        BOOST_TEST(np_udp_create(&pl_->udp, &socket_) == NABTO_EC_OK);

        uint8_t addr[] = { 0x7F, 0x00, 0x00, 0x01 };

        for (size_t i = 0; i < data_.size(); i++) {
            data_[i] = (uint8_t)i;
        }

        ep_.ip.type = NABTO_IPV4;
        memcpy(ep_.ip.ip.v6, addr, 4);
        ep_.port = port;

        np_completion_event_reinit(&completionEvent_, &UdpEchoClientTest::created, this);
        np_udp_async_bind_port(&pl_->udp, socket_, 0, &completionEvent_);
    }

    static void created(const np_error_code ec, void* data)
    {
        BOOST_TEST(ec == NABTO_EC_OK);
        UdpEchoClientTest* client = (UdpEchoClientTest*)data;
        client->startSend();
    }

    void startSend()
    {
        np_completion_event_reinit(&completionEvent_, &UdpEchoClientTest::sent, this);
        np_udp_async_send_to(&pl_->udp, socket_, &ep_, data_.data(), data_.size(), &completionEvent_);
    }

    static void sent(np_error_code ec, void* data)
    {
        UdpEchoClientTest* client = (UdpEchoClientTest*)data;
        BOOST_TEST(ec == NABTO_EC_OK, np_error_code_to_string(ec));
        client->startRecv();
    }

    void startRecv()
    {
        np_completion_event_reinit(&completionEvent_, &UdpEchoClientTest::received, this);
        np_udp_async_recv_wait(&pl_->udp, socket_, &completionEvent_);
    }

    static void received(np_error_code ec, void* data)
    {
        UdpEchoClientTest* client = (UdpEchoClientTest*)data;

        struct np_udp_endpoint ep;
        uint8_t buffer[1500];
        size_t bufferSize = 1500;
        size_t recvLength;

        BOOST_TEST(ec == NABTO_EC_OK);
        BOOST_TEST(np_udp_recv_from(&client->pl_->udp, client->socket_, &ep, buffer, bufferSize, &recvLength) == NABTO_EC_OK);

        auto sentData = lib::span<const uint8_t>(client->data_.data(), client->data_.size());
        auto receivedData = lib::span<const uint8_t>(buffer, recvLength);
        BOOST_TEST(sentData == receivedData);
        client->end();
    }

    void end() {
        np_udp_destroy(&pl_->udp, socket_);
        testEnded_.set_value();
    }

    void waitForTestEnded() {
        std::future<void> fut = testEnded_.get_future();
        fut.get();
    }

 private:
    nabto::test::TestPlatform& tp_;
    struct np_platform* pl_;
    struct np_event_queue eq_;
    struct np_udp_endpoint ep_;
    struct np_udp_socket* socket_;
    std::array<uint8_t, 42> data_;
    std::vector<uint8_t> recvBuffer_;
    struct np_completion_event completionEvent_;
    std::promise<void> testEnded_;

};

} } // namespace



BOOST_AUTO_TEST_SUITE(udp)

BOOST_TEST_DECORATOR(* boost::unit_test::timeout(120))
BOOST_DATA_TEST_CASE(echo, nabto::test::TestPlatformFactory::multi(), tpf)
{
    auto ioService = nabto::IoService::create("test");
    auto udpServer = nabto::test::UdpEchoServer::create(ioService->getIoService());

    auto tp = tpf->create();

    nabto::test::UdpEchoClientTest client(*tp);
    client.start(udpServer->getPort());
    client.waitForTestEnded();

    BOOST_TEST(udpServer->getPacketCount() > (uint64_t)0);
    udpServer->stop();
}


BOOST_AUTO_TEST_SUITE_END()
