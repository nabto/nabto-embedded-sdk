#include <iostream>

#include <util/udp_echo_server.hpp>
#include <util/io_service.hpp>
#include <util/termination_waiter.hpp>

#include <nn/log.h>

#include <stdio.h>

static uint16_t udpEchoServerPort = 1234;



void log_print(void* userData, enum nn_log_severity severity, const char* module, const char* file, int line, const char* fmt, va_list args)
{
    vprintf(fmt, args);
    std::cout << std::endl;
}

int main(int argc, const char* argv[])
{
    std::cout << "starting platform integration stub" << std::endl;

    struct nn_log logger;
    nn_log_init(&logger, &log_print, NULL);

    auto ioService = nabto::IoService::create("platform_integration_stub");

    auto udpEchpServer = nabto::test::UdpEchoServer::create(ioService->getIoService(), &logger, udpEchoServerPort);


    if (udpEchpServer) {
        std::cout << "Udp echo server listening on port " << udpEchoServerPort << std::endl;
    }

    std::cout << "Waiting for CTRL-C" << std::endl;
    nabto::CtrlCWaiter::waitForTermination();
}
