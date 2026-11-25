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
#include <util/test_owner.hpp>

namespace {
// Owner of the completion events and modules created by the tests.
nabto::test::TestOwner testOwner;
}


using namespace nabto;

namespace nabto {
namespace test {

class TcpEchoClientTest {
 public:
    TcpEchoClientTest(TestPlatform& tp)
        : pl_(tp.getPlatform()), tcp_(pl_->tcp), eq_(pl_->eq)
    {
        np_completion_event_init(&eq_, &completionEvent_, NULL, NULL, &testOwner.ref);
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
        : pl_(tp.getPlatform()), tcp_(pl_->tcp), eq_(pl_->eq)
    {
        np_completion_event_init(&eq_, &completionEvent_, NULL, NULL, &testOwner.ref);
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

// Starting a connect or a read while one is already pending has to fail the
// new operation with NABTO_EC_OPERATION_IN_PROGRESS and leave the pending
// operation alone.
class TcpPendingOperationTest {
 public:
    TcpPendingOperationTest(TestPlatform& tp)
        : pl_(tp.getPlatform()), tcp_(pl_->tcp), eq_(pl_->eq)
    {
        np_completion_event_init(&eq_, &connectEvent_, &TcpPendingOperationTest::connected, this, &testOwner.ref);
        np_completion_event_init(&eq_, &secondConnectEvent_, &TcpPendingOperationTest::secondConnected, this, &testOwner.ref);
        np_completion_event_init(&eq_, &readEvent_, &TcpPendingOperationTest::hasReaden, this, &testOwner.ref);
        np_completion_event_init(&eq_, &secondReadEvent_, &TcpPendingOperationTest::secondHasReaden, this, &testOwner.ref);
    }

    ~TcpPendingOperationTest()
    {
        np_completion_event_deinit(&connectEvent_);
        np_completion_event_deinit(&secondConnectEvent_);
        np_completion_event_deinit(&readEvent_);
        np_completion_event_deinit(&secondReadEvent_);
    }

    void start(uint16_t port) {
        BOOST_TEST(np_tcp_create(&tcp_, &socket_) == NABTO_EC_OK);

        struct np_ip_address address;
        address.type = NABTO_IPV4;
        uint8_t addr[] = { 0x7f, 0x00, 0x00, 0x01 };
        memcpy(address.ip.v4, addr, 4);

        np_tcp_async_connect(&tcp_, socket_, &address, port, &connectEvent_);
        np_tcp_async_connect(&tcp_, socket_, &address, port, &secondConnectEvent_);
    }

    static void secondConnected(np_error_code ec, void* userData)
    {
        auto test = (TcpPendingOperationTest*)userData;
        test->secondConnectCount_++;
        test->secondConnectEc_ = ec;
    }

    static void connected(np_error_code ec, void* userData)
    {
        auto test = (TcpPendingOperationTest*)userData;
        test->connectEc_ = ec;
        if (ec != NABTO_EC_OK) {
            test->end();
            return;
        }
        // The echo server does not send anything, so the first read stays
        // pending.
        np_tcp_async_read(&test->tcp_, test->socket_, test->recvBuffer_.data(), test->recvBuffer_.size(), &test->readLength_, &test->readEvent_);
        np_tcp_async_read(&test->tcp_, test->socket_, test->recvBuffer2_.data(), test->recvBuffer2_.size(), &test->readLength2_, &test->secondReadEvent_);
    }

    static void secondHasReaden(np_error_code ec, void* userData)
    {
        auto test = (TcpPendingOperationTest*)userData;
        test->secondReadCount_++;
        test->secondReadEc_ = ec;
        np_tcp_abort(&test->tcp_, test->socket_);
    }

    static void hasReaden(np_error_code ec, void* userData)
    {
        auto test = (TcpPendingOperationTest*)userData;
        test->readCount_++;
        if (test->readCount_ == 1) {
            test->readEc_ = ec;
            test->end();
        }
    }

    void end() {
        np_tcp_destroy(&tcp_, socket_);
        testEnded_.set_value();
    }

    bool waitForTestEnded() {
        std::future<void> fut = testEnded_.get_future();
        return fut.wait_for(std::chrono::seconds(30)) == std::future_status::ready;
    }

    np_error_code connectEc_ = NABTO_EC_FAILED;
    np_error_code secondConnectEc_ = NABTO_EC_FAILED;
    int secondConnectCount_ = 0;
    np_error_code readEc_ = NABTO_EC_FAILED;
    int readCount_ = 0;
    np_error_code secondReadEc_ = NABTO_EC_FAILED;
    int secondReadCount_ = 0;

 private:
    struct np_platform* pl_;
    struct np_tcp_socket* socket_;
    std::array<uint8_t, 42> recvBuffer_;
    std::array<uint8_t, 42> recvBuffer2_;
    size_t readLength_;
    size_t readLength2_;
    struct np_completion_event connectEvent_;
    struct np_completion_event secondConnectEvent_;
    struct np_completion_event readEvent_;
    struct np_completion_event secondReadEvent_;
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

// A socket which has been created but not connected yet has no file
// descriptor. The platform has to handle traffic on other sockets meanwhile.
BOOST_TEST_DECORATOR(* boost::unit_test::timeout(120))
BOOST_DATA_TEST_CASE(echo_with_unconnected_socket, nabto::test::TestPlatformFactory::multi(), tpf)
{
    auto tp = tpf->create();
    auto ioService = IoService::create("test");
    test::TcpEchoServer tcpServer(ioService->getIoService(), nullptr);

    struct np_tcp tcp = tp->getPlatform()->tcp;
    struct np_tcp_socket* unconnected = NULL;
    BOOST_TEST(np_tcp_create(&tcp, &unconnected) == NABTO_EC_OK);

    test::TcpEchoClientTest client(*tp);
    client.start(tcpServer.getPort());

    client.waitForTestEnded();

    np_tcp_destroy(&tcp, unconnected);
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

BOOST_TEST_DECORATOR(* boost::unit_test::timeout(120))
BOOST_DATA_TEST_CASE(operation_in_progress, nabto::test::TestPlatformFactory::multi(), tpf)
{
    auto tp = tpf->create();
    auto ioService = IoService::create("test");
    test::TcpEchoServer tcpServer(ioService->getIoService(), nullptr);

    test::TcpPendingOperationTest client(*tp);
    client.start(tcpServer.getPort());
    BOOST_REQUIRE(client.waitForTestEnded());

    BOOST_TEST(client.connectEc_ == NABTO_EC_OK);
    BOOST_TEST(client.secondConnectCount_ == 1);
    BOOST_TEST(client.secondConnectEc_ == NABTO_EC_OPERATION_IN_PROGRESS);
    BOOST_TEST(client.secondReadCount_ == 1);
    BOOST_TEST(client.secondReadEc_ == NABTO_EC_OPERATION_IN_PROGRESS);
    BOOST_TEST(client.readCount_ == 1);
    BOOST_TEST(client.readEc_ == NABTO_EC_ABORTED);
}

BOOST_AUTO_TEST_SUITE_END()
