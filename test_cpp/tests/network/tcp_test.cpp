#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <test_platform.hpp>

#include <platform/np_ip_address.h>
#include <platform/np_error_code.h>
#include <platform/interfaces/np_tcp.h>
#include <platform/np_platform.h>
#include <platform/np_completion_event.h>
#include <platform/np_tcp_wrapper.h>


#include <util/io_service.hpp>
#include <util/tcp_echo_server.hpp>

#include <boost/asio.hpp>

#include <util/span.hpp>

#include <set>
#include <memory>
#include <iostream>
#include <array>

using namespace nabto;

namespace nabto {
namespace test {

class TcpEchoClientTest {
 public:
    TcpEchoClientTest(TestPlatform& tp)
        :tp_(tp), pl_(tp.getPlatform()), tcp_(pl_->tcp), eq_(pl_->eq)
    {
        np_completion_event_init(&eq_, &completionEvent_, NULL, NULL);
    }

    ~TcpEchoClientTest() {
        np_completion_event_deinit(&completionEvent_);
    }

    void start(uint16_t port) {
        BOOST_TEST(np_tcp_create(&tcp_, &socket_) == NABTO_EC_OK);

        struct np_ip_address address;
        address.type = NABTO_IPV4;
        uint8_t addr[] = { 0x7f, 0x00, 0x00, 0x01 };
        memcpy(address.ip.v4, addr, 4);

        for (size_t i = 0; i < data_.size(); i++) {
            data_[i] = (uint8_t)i;
        }

        np_completion_event_reinit(&completionEvent_, &TcpEchoClientTest::connected, this);
        np_tcp_async_connect(&tcp_, socket_, &address, port, &completionEvent_);
    }

    static void connected(np_error_code ec, void* userData)
    {
        auto test = (TcpEchoClientTest*)userData;
        BOOST_TEST(ec == NABTO_EC_OK);
        np_completion_event_reinit(&test->completionEvent_, &TcpEchoClientTest::hasWritten, test);
        np_tcp_async_write(&test->tcp_, test->socket_, test->data_.data(), test->data_.size(), &test->completionEvent_);
    }

    static void hasWritten(np_error_code ec, void* userData)
    {
        auto test = (TcpEchoClientTest*)userData;
        BOOST_TEST(ec == NABTO_EC_OK);
        test->recvBuffer_.resize(test->data_.size());
        np_completion_event_reinit(&test->completionEvent_, &TcpEchoClientTest::hasReaden, test);
        np_tcp_async_read(&test->tcp_, test->socket_, test->recvBuffer_.data(), test->recvBuffer_.size(), &test->readLength_, &test->completionEvent_);
    }

    static void hasReaden(np_error_code ec, void* userData)
    {
        auto test = (TcpEchoClientTest*)userData;
        // TODO fix lazy written test case, if data is split up readen is less than data_.size()
        BOOST_TEST(ec == NABTO_EC_OK);
        BOOST_TEST(test->readLength_ == test->data_.size());
        auto sentData = lib::span<const uint8_t>(test->data_.data(), test->data_.size());
        auto receivedData = lib::span<const uint8_t>(test->recvBuffer_.data(), test->recvBuffer_.size());
        BOOST_TEST(sentData == receivedData);
        np_tcp_abort(&test->tcp_, test->socket_);
        test->end();
    }

    void end() {
        np_tcp_destroy(&tcp_, socket_);
        testEnded_.set_value();
    }
    void waitForTestEnded() {
        std::future<void> fut = testEnded_.get_future();
        fut.get();
    }

 private:
    TestPlatform& tp_;
    struct np_platform* pl_;
    struct np_tcp_socket* socket_;
    std::array<uint8_t, 42> data_;
    std::vector<uint8_t> recvBuffer_;
    size_t readLength_;
    struct np_completion_event completionEvent_;
    struct np_tcp tcp_;
    struct np_event_queue eq_;
    std::promise<void> testEnded_;
};

class TcpCloseClientTest {
 public:
    TcpCloseClientTest(TestPlatform& tp)
        :tp_(tp), pl_(tp.getPlatform()), tcp_(pl_->tcp), eq_(pl_->eq)
    {
        np_completion_event_init(&eq_, &completionEvent_, NULL, NULL);
    }

    ~TcpCloseClientTest()
    {
        np_completion_event_deinit(&completionEvent_);
    }

    void createSock() {
        BOOST_TEST(np_tcp_create(&tcp_, &socket_) == NABTO_EC_OK);

        struct np_ip_address address;
        address.type = NABTO_IPV4;
        uint8_t addr[] = { 0x7f, 0x00, 0x00, 0x01 };
        memcpy(address.ip.v4, addr, 4);

        for (size_t i = 0; i < data_.size(); i++) {
            data_[i] = (uint8_t)i;
        }
        np_completion_event_reinit(&completionEvent_, &TcpCloseClientTest::connected, this);
        np_tcp_async_connect(&tcp_, socket_, &address, port_, &completionEvent_);
    }

    void start(uint16_t port) {
        port_ = port;
        createSock();
    }

    static void connected(np_error_code ec, void* userData)
    {
        auto test = (TcpCloseClientTest*)userData;
        BOOST_TEST(ec == NABTO_EC_OK);
        np_completion_event_reinit(&test->completionEvent_, &TcpCloseClientTest::hasReaden, test);
        np_tcp_async_read(&test->tcp_, test->socket_, test->recvBuffer_.data(), test->recvBuffer_.size(), &test->readLength_, &test->completionEvent_);
        np_tcp_abort(&test->tcp_, test->socket_);
    }

    static void hasReaden(np_error_code ec, void* userData)
    {
        auto test = (TcpCloseClientTest*)userData;
        BOOST_TEST(ec == NABTO_EC_ABORTED, "ec was not ABORTED: " << ec);
        test->end();
    }

    void end() {
        np_tcp_destroy(&tcp_, socket_);
        testEnded_.set_value();
    }
    void waitForTestEnded() {
        std::future<void> fut = testEnded_.get_future();
        fut.get();
    }
 private:
    TestPlatform& tp_;
    struct np_platform* pl_;

    struct np_tcp_socket* socket_;
    std::array<uint8_t, 42> data_;
    std::vector<uint8_t> recvBuffer_;
    size_t readLength_;
    uint16_t port_;
    struct np_completion_event completionEvent_;
    struct np_tcp tcp_;
    struct np_event_queue eq_;
    std::promise<void> testEnded_;
};

} }

BOOST_TEST_DONT_PRINT_LOG_VALUE( std::vector<std::unique_ptr<nabto::test::TestPlatform> >)
BOOST_TEST_DONT_PRINT_LOG_VALUE( std::unique_ptr<nabto::test::TestPlatform>)

BOOST_AUTO_TEST_SUITE(tcp)

BOOST_TEST_DECORATOR(* boost::unit_test::timeout(120))
BOOST_DATA_TEST_CASE(echo, nabto::test::TestPlatformFactory::multi(), tpf)
{
    auto tp = tpf->create();
    auto ioService = IoService::create("test");
    test::TcpEchoServer tcpServer(ioService->getIoService(), nullptr);

    test::TcpEchoClientTest client(*tp);
    client.start(tcpServer.getPort());

    client.waitForTestEnded();

    BOOST_TEST(tcpServer.getConnectionsCount() > (size_t)0);
}

BOOST_TEST_DECORATOR(* boost::unit_test::timeout(120))
BOOST_DATA_TEST_CASE(close, nabto::test::TestPlatformFactory::multi(), tpf)
{
    auto tp = tpf->create();
    auto ioService = IoService::create("test");
    test::TcpEchoServer tcpServer(ioService->getIoService(), nullptr);

    test::TcpCloseClientTest client(*tp);
    client.start(tcpServer.getPort());
    client.waitForTestEnded();
//    BOOST_TEST(tcpServer.getConnectionsCount() > (size_t)0);
}

BOOST_AUTO_TEST_SUITE_END()
