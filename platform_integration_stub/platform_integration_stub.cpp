#include <iostream>

#include <util/udp_echo_server.hpp>
#include <util/io_service.hpp>
#include <util/termination_waiter.hpp>

static uint16_t udpEchoServerPort = 1234;

int main(int argc, const char* argv[])
{
    std::cout << "starting platform integration stub" << std::endl;

    auto ioService = nabto::IoService::create("platform_integration_stub");

    auto udpEchpServer = nabto::test::UdpEchoServer::create(ioService->getIoService(), udpEchoServerPort);

    if (udpEchpServer) {
        std::cout << "Udp echo server listening on port " << udpEchoServerPort << std::endl;
    }

    std::cout << "Waiting for CTRL-C" << std::endl;
    nabto::CtrlCWaiter::waitForTermination();
}
