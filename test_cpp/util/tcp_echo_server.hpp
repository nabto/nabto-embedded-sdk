#pragma once

#include <nn/log.h>

#include <boost/asio.hpp>

#include <set>

#define LOG_MODULE "tcp_echo_server"

namespace nabto {
namespace test {

class TcpEchoServerImpl;

class TcpEchoConnection : public std::enable_shared_from_this<TcpEchoConnection> {
 public:
    TcpEchoConnection(std::shared_ptr<TcpEchoServerImpl> manager, boost::asio::io_context& io, struct nn_log* logger)
        : manager_(manager), socket_(io), logger_(logger)
    {
    }

    ~TcpEchoConnection();

    static std::shared_ptr<TcpEchoConnection> create(std::shared_ptr<TcpEchoServerImpl> manager, boost::asio::io_context& io, struct nn_log* logger)
    {
        auto c = std::make_shared<TcpEchoConnection>(manager, io, logger);
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

    std::string remoteEpString()
    {
        boost::system::error_code ec;
        boost::asio::ip::tcp::endpoint remote = socket_.remote_endpoint(ec);
        std::stringstream ss;
        ss << remote.address().to_string();
        ss << ":" << remote.port();
        return ss.str();
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
                NN_LOG_TRACE(self->logger_, LOG_MODULE, "TCP connection read %d bytes from %s", transferred, self->remoteEpString().c_str());
                boost::asio::async_write(
                    self->socket_, boost::asio::buffer(self->recvBuffer_.data(), transferred),
                    [self](const boost::system::error_code& ec, std::size_t transferred) {
                        if (ec) {
                            self->stopFromSelf();
                            return;
                        }
                        NN_LOG_TRACE(self->logger_, LOG_MODULE, "TCP connection sent %d bytes to %s", transferred, self->remoteEpString().c_str());
                        self->startRead();
                    });
            });
    }

 private:
    std::shared_ptr<TcpEchoServerImpl> manager_;
    boost::asio::ip::tcp::socket socket_;
    std::array<uint8_t, 1500> recvBuffer_;
    struct nn_log* logger_;

};

class TcpEchoServerImpl : public std::enable_shared_from_this<TcpEchoServerImpl> {
 public:
    TcpEchoServerImpl(boost::asio::io_context& io, struct nn_log* logger, uint16_t port)
        : io_(io), acceptor_(io, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)), logger_(logger)
    {
    }
    static std::shared_ptr<TcpEchoServerImpl> create(boost::asio::io_context& io, struct nn_log* logger, uint16_t port)
    {
        auto s = std::make_shared<TcpEchoServerImpl>(io, logger, port);
        s->init();
        return s;
    }

    void init() {
        startAccept();
    }

    void startAccept() {
        auto self = shared_from_this();
        auto c = TcpEchoConnection::create(shared_from_this(), io_, logger_);
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
        auto self = shared_from_this();
        io_.post([self](){
                self->acceptor_.close();
                for (auto c : self->connections_) {
                    self->io_.post([c](){ c->stopFromManager(); });
                }
            });
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
    struct nn_log* logger_;
};

class TcpEchoServer {
 public:
    TcpEchoServer(boost::asio::io_context& io, struct nn_log* logger)
    {
        impl_ = TcpEchoServerImpl::create(io, logger, 0);
    }
    TcpEchoServer(boost::asio::io_context& io, struct nn_log* logger, uint16_t port)
    {
        impl_ = TcpEchoServerImpl::create(io, logger, port);
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

} } // namespace
