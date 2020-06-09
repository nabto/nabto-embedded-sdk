#include "tcp_echo_server.hpp"

namespace nabto {
namespace test {

TcpEchoConnection::~TcpEchoConnection() {
}

void TcpEchoConnection::stopFromSelf()
{
    manager_->removeConnection(shared_from_this());
    NN_LOG_TRACE(logger_, LOG_MODULE, "TCP connection closed remote endpoint %s", remoteEpString().c_str());
}

void TcpEchoConnection::start()
{
    manager_->addConnection(shared_from_this());
    NN_LOG_TRACE(logger_, LOG_MODULE, "TCP connection accepted from %s", remoteEpString().c_str());

    startRead();
}

} } // namespace
