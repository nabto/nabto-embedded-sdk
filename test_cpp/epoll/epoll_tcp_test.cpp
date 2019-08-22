#include <boost/test/unit_test.hpp>

#include <modules/epoll/nm_epoll.h>
#include <test_platform/test_platform.h>

#include <platform/np_ip_address.h>

#include <util/io_service.hpp>

#include <boost/asio.hpp>

#include <lib/span.hpp>

#include <set>
#include <memory>
#include <iostream>
#include <array>

using namespace nabto;

namespace nabto {
namespace test {

class TcpEchoServerImpl;

class TcpEchoConnection : public std::enable_shared_from_this<TcpEchoConnection> {
 public:
    TcpEchoConnection(std::shared_ptr<TcpEchoServerImpl> manager, boost::asio::io_context& io)
        : manager_(manager), socket_(io)
    {
    }

    ~TcpEchoConnection();

    static std::shared_ptr<TcpEchoConnection> create(std::shared_ptr<TcpEchoServerImpl> manager, boost::asio::io_context& io)
    {
        auto c = std::make_shared<TcpEchoConnection>(manager, io);
        return c;
    }

    boost::asio::ip::tcp::socket& getSocket()
    {
        return socket_;
    }

    void start();

    void stopFromManager() {
        boost::system::error_code ec;
        socket_.close(ec);

        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    }

    void stopFromSelf();

    void startRead() {
        auto self = shared_from_this();
        socket_.async_read_some(
            boost::asio::buffer(recvBuffer_),
            [self](const boost::system::error_code& ec, std::size_t transferred)
            {
                if (ec) {
                    self->stopFromSelf();
                    return;
                }
                boost::asio::async_write(
                    self->socket_, boost::asio::buffer(self->recvBuffer_.data(), transferred),
                    [self](const boost::system::error_code& ec, std::size_t transferred) {
                        if (ec) {
                            self->stopFromSelf();
                            return;
                        }
                        self->startRead();
                    });
            });
    }

 private:
    std::shared_ptr<TcpEchoServerImpl> manager_;
    boost::asio::ip::tcp::socket socket_;
    std::array<uint8_t, 1500> recvBuffer_;

};

class TcpEchoServerImpl : public std::enable_shared_from_this<TcpEchoServerImpl> {
 public:
    TcpEchoServerImpl(boost::asio::io_context& io)
        : io_(io), acceptor_(io, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0))
    {
    }
    static std::shared_ptr<TcpEchoServerImpl> create(boost::asio::io_context& io)
    {
        auto s = std::make_shared<TcpEchoServerImpl>(io);
        s->init();
        return s;
    }

    void init() {
        startAccept();
    }

    void startAccept() {
        auto self = shared_from_this();
        auto c = TcpEchoConnection::create(shared_from_this(), io_);
        acceptor_.async_accept(c->getSocket(), [self, c](const boost::system::error_code& ec) {
                if (ec) {
                    return;
                }
                self->connectionsCount_ += 1;
                c->start();
                self->startAccept();
            });
    }

    void stop() {
        acceptor_.close();
        for (auto c : connections_) {
            io_.post([c](){ c->stopFromManager(); });
        }
    }

    uint16_t getPort() {
        boost::system::error_code ec;
        boost::asio::ip::tcp::endpoint ep = acceptor_.local_endpoint(ec);
        return ep.port();
    }

    size_t getConnectionsCount() {
        return connectionsCount_;
    }

    void removeConnection(std::shared_ptr<TcpEchoConnection> connection)
    {
        connections_.erase(connection);
    }

    void addConnection(std::shared_ptr<TcpEchoConnection> connection)
    {
        connections_.insert(connection);
    }
 private:
    boost::asio::io_context& io_;
    boost::asio::ip::tcp::acceptor acceptor_;

    std::atomic<std::size_t> connectionsCount_ = { 0 };
    std::set<std::shared_ptr<TcpEchoConnection> > connections_;
};

class TcpEchoServer {
 public:
    TcpEchoServer(boost::asio::io_context& io)
    {
        impl_ = TcpEchoServerImpl::create(io);
    }
    ~TcpEchoServer()
    {
        impl_->stop();
    }
    uint16_t getPort() {
        return impl_->getPort();
    }

    size_t getConnectionsCount() {
        return impl_->getConnectionsCount();
    }
 private:
    std::shared_ptr<TcpEchoServerImpl> impl_;
};


TcpEchoConnection::~TcpEchoConnection() {
}

void TcpEchoConnection::stopFromSelf()
{
    manager_->removeConnection(shared_from_this());
}

void TcpEchoConnection::start()
{
    manager_->addConnection(shared_from_this());
    startRead();
}


class TcpEchoClientTest {
 public:
    TcpEchoClientTest() {
    }
    void start(uint16_t port) {
        test_platform_init(&tp_);

        pl_ = &tp_.pl;
        BOOST_TEST(pl_->tcp.create(pl_, &socket_) == NABTO_EC_OK);

        struct np_ip_address address;
        address.type = NABTO_IPV4;
        uint8_t addr[] = { 0x7f, 0x00, 0x00, 0x01 };
        memcpy(address.v4.addr, addr, 4);

        for (size_t i = 0; i < data_.size(); i++) {
            data_[i] = (uint8_t)i;
        }

        BOOST_TEST(pl_->tcp.async_connect(socket_, &address, port, &TcpEchoClientTest::connected, this) == NABTO_EC_OK);

        test_platform_run(&tp_);


    }

    static void connected(np_error_code ec, void* userData)
    {
        auto test = (TcpEchoClientTest*)userData;
        BOOST_TEST(ec == NABTO_EC_OK);
        BOOST_TEST(test->pl_->tcp.async_write(test->socket_, test->data_.data(), test->data_.size(), &TcpEchoClientTest::hasWritten, test) == NABTO_EC_OK);
    }

    static void hasWritten(np_error_code ec, void* userData)
    {
        auto test = (TcpEchoClientTest*)userData;
        BOOST_TEST(ec == NABTO_EC_OK);
        test->recvBuffer_.resize(test->data_.size());
        BOOST_TEST(test->pl_->tcp.async_read(test->socket_, test->recvBuffer_.data(), test->recvBuffer_.size(), &TcpEchoClientTest::hasReaden, test) == NABTO_EC_OK);
    }

    static void hasReaden(np_error_code ec, size_t readen, void* userData)
    {
        auto test = (TcpEchoClientTest*)userData;
        // TODO fix lazy written test case, if data is split up readen is less than data_.size()
        BOOST_TEST(ec == NABTO_EC_OK);
        BOOST_TEST(readen == test->data_.size());
        auto sentData = lib::span<const uint8_t>(test->data_.data(), test->data_.size());
        auto receivedData = lib::span<const uint8_t>(test->recvBuffer_.data(), test->recvBuffer_.size());
        BOOST_TEST(sentData == receivedData);
        BOOST_TEST(test->pl_->tcp.close(test->socket_) == NABTO_EC_OK);
        test->end();
    }

    void end() {
        test_platform_stop(&tp_);
    }
 private:
    struct test_platform tp_;
    struct np_platform* pl_;
    np_tcp_socket* socket_;
    std::array<uint8_t, 42> data_;
    std::vector<uint8_t> recvBuffer_;
};

} }

BOOST_AUTO_TEST_SUITE(epoll_tcp)

BOOST_AUTO_TEST_CASE(echo)
{
    auto ioService = IoService::create("test");
    test::TcpEchoServer tcpServer(ioService->getIoService());

    test::TcpEchoClientTest client;
    client.start(tcpServer.getPort());

    BOOST_TEST(tcpServer.getConnectionsCount() > (size_t)0);
}

BOOST_AUTO_TEST_SUITE_END()
