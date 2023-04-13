#include <stdio.h>

#include <nabto/nabto_device_test.h>

#include <util/io_service.hpp>
#include <util/tcp_echo_server.hpp>
#include <util/udp_echo_server.hpp>

#include <iostream>

static void test_create_free() 
{
    for (int i = 0; i < 10; i++) {
        NabtoDevice* device = nabto_device_test_new();
        nabto_device_test_free(device);
    }
}

static void udp_test(const std::string& host, uint16_t port) 
{
    NabtoDevice* device = nabto_device_test_new();

    NabtoDeviceFuture* f = nabto_device_future_new(device);

    nabto_device_set_log_std_out_callback(device);

    nabto_device_test_udp(device, host.c_str(), port, f);

    NabtoDeviceError ec = nabto_device_future_wait(f);

    if (ec != NABTO_DEVICE_EC_OK) {
        printf("UDP test failed\n");
    } else {
        printf("UDP test succeeded\n");
    }

    nabto_device_future_free(f);
    nabto_device_test_free(device);
}


static void tcp_test(const std::string& host, uint16_t port) 
{
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

void local_ip_test() 
{
    NabtoDevice* device = nabto_device_test_new();
    nabto_device_test_local_ip(device);
    nabto_device_test_free(device);
}

void dns_test() {
    NabtoDevice* device = nabto_device_test_new();
    NabtoDeviceFuture* f = nabto_device_future_new(device);
    nabto_device_test_dns(device, f);
    NabtoDeviceError ec = nabto_device_future_wait(f);

    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Dns test failed\n");
    } else {
        printf("Dns test succeeded\n");
    }
    nabto_device_future_free(f);
    nabto_device_test_free(device);
}

void event_queue_test()
{
    NabtoDevice* device = nabto_device_test_new();
    NabtoDeviceFuture* f = nabto_device_future_new(device);
    nabto_device_test_event_queue(device, f);
    NabtoDeviceError ec = nabto_device_future_wait(f);

    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Event queue test failed\n");
    } else {
        printf("Event queue test succeeded\n");
    }
    nabto_device_future_free(f);
    nabto_device_test_free(device);
}

void future_resolve_test()
{
    NabtoDevice* device = nabto_device_test_new();
    NabtoDeviceFuture* f = nabto_device_future_new(device);
    nabto_device_test_future_resolve(device, f);
    NabtoDeviceError ec = nabto_device_future_wait(f);

    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Future resolve test failed\n");
    } else {
        printf("Future resolve test succeeded\n");
    }
    nabto_device_future_free(f);
    nabto_device_test_free(device);
}

void logging_test() 
{
    NabtoDevice* device = nabto_device_test_new();
    nabto_device_set_log_std_out_callback(device);
    nabto_device_set_log_level(device, "trace");


    nabto_device_test_logging(device);
    nabto_device_set_log_level(device, "info");

    nabto_device_test_free(device);
}

void mdns_test() {
    NabtoDevice* device = nabto_device_test_new();
    nabto_device_test_mdns_publish_service(device);
    do 
    {
        std::cout << '\n' << "Press a key to continue...";
    } while (std::cin.get() != '\n');
    nabto_device_test_free(device);
}

void testLoop() {
    nabto::IoServicePtr ioService = nabto::IoService::create("test");
    nabto::test::TcpEchoServer tcpEchoServer(ioService->getIoService(), NULL);
    nabto::test::UdpEchoServer udpEchoServer(ioService->getIoService(), NULL);
    for (int i = 0; i < 10; i++) {
        test_create_free();

        logging_test();
        future_resolve_test();
        event_queue_test();
        dns_test();
        udp_test("127.0.0.1", udpEchoServer.getPort());
        tcp_test("127.0.0.1", tcpEchoServer.getPort());
        local_ip_test();
    }

    mdns_test();
}

int main() {
    testLoop();
}
