#include <boost/test/unit_test.hpp>

#include <util/io_service.hpp>

#include <boost/asio.hpp>

#include <nabto/nabto_device.h>

// start a device test that it can be udp pinged on both the local and the remote port numbers.


BOOST_AUTO_TEST_SUITE(local_ping)

BOOST_AUTO_TEST_CASE(ping_device, *boost::unit_test::timeout(300))
{
    NabtoDevice* device = nabto_device_new();

    nabto_device_set_product_id(device, "pr-abcdefgh");
    nabto_device_set_device_id(device, "de-12345678");
    nabto_device_set_local_port(device, 0);
    nabto_device_set_p2p_port(device, 0);
    char* key;
    nabto_device_create_private_key(device, &key);
    nabto_device_set_private_key(device, key);
    nabto_device_string_free(key);

    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    nabto_device_start(device, fut);
    BOOST_TEST(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_OK);
    nabto_device_future_free(fut);

    auto ioService = nabto::IoService::create("test");

    boost::asio::ip::udp::socket socket(ioService->getIoService());
    socket.open(boost::asio::ip::udp::v4());

    std::vector<uint8_t> packet;
    packet.push_back(241);
    for (uint8_t i = 0; i < 15; i++) {
        packet.push_back(i);
    }
    packet.push_back(4); // ping request

    std::vector<boost::asio::ip::udp::endpoint> eps;

    uint16_t localPort;
    uint16_t p2pPort;
    nabto_device_get_local_port(device, &localPort);
    nabto_device_get_p2p_port(device, &p2pPort);

    eps.push_back(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), localPort));
    eps.push_back(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), p2pPort));

    for (auto ep : eps) {
        socket.send_to(boost::asio::buffer(packet.data(), packet.size()), ep, 0);

        std::vector<uint8_t> buffer(42);
        boost::asio::ip::udp::endpoint recvEp;

        std::size_t received = socket.receive_from(boost::asio::buffer(buffer.data(), buffer.size()), recvEp);
        BOOST_TEST(received == (size_t)17);

        for (size_t i = 0; i < 16; i++) {
            BOOST_TEST(buffer[i] == packet[i]);
        }
        BOOST_TEST(buffer[16] == 5); // response
    }

    nabto_device_free(device);
}

BOOST_AUTO_TEST_SUITE_END();
