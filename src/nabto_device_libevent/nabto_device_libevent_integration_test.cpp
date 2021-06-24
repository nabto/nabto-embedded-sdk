#include <stdio.h>

#include <nabto/nabto_device_test.h>

#include <util/io_service.hpp>
#include <util/tcp_echo_server.hpp>

static void tcp_test(const std::string& host, uint16_t port) {
    NabtoDevice* device = nabto_device_test_new();

    NabtoDeviceFuture* f = nabto_device_future_new(device);

    nabto_device_set_log_std_out_callback(device);

    nabto_device_test_tcp(device, host.c_str(), port, f);

    NabtoDeviceError ec = nabto_device_future_wait(f);

    if (ec != NABTO_DEVICE_EC_OK) {
        printf("TCP test failed\n");
    } else {
        printf("TCP test succeeded\n");
    }

    nabto_device_future_free(f);
    nabto_device_test_free(device);
}

void logging_test() {
    NabtoDevice* device = nabto_device_test_new();
    nabto_device_set_log_std_out_callback(device);
    nabto_device_set_log_level(device, "trace");


    nabto_device_test_logging(device);
    nabto_device_set_log_level(device, "info");

    nabto_device_test_free(device);
}

int main() {

    nabto::IoServicePtr ioService = nabto::IoService::create("test");
    nabto::test::TcpEchoServer tcpEchoServer(ioService->getIoService(), NULL);

    logging_test();
    tcp_test("127.0.0.1", tcpEchoServer.getPort());
}
