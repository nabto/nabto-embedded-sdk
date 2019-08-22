#include <boost/test/unit_test.hpp>

#include <util/io_service.hpp>

using namespace nabto;

namespace nabto {
namespace test {

class TcpEchoServer {
 public:
    TcpEchoServer(boost::asio::io_context& io)
    {
    }
 private:

};

} }

BOOST_AUTO_TEST_SUITE(epoll_tcp)

BOOST_AUTO_TEST_CASE(connect)
{
    auto ioService = IoService::create("test");
    test::TcpEchoServer tcpServer(ioService->getIoService());

}

BOOST_AUTO_TEST_CASE(echo)
{

}

BOOST_AUTO_TEST_SUITE_END()
