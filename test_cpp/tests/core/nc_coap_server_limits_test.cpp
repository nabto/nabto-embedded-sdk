#include <boost/test/unit_test.hpp>

#include <test_platform.hpp>

#include <api/nabto_device_defines.h>
#include <core/nc_coap_server.h>
#include <nabto/nabto_device.h>

#include <vector>

namespace {

struct HandlerState {
    size_t calls = 0;
};

void count_handler(struct nc_coap_server_request* request, void* userData)
{
    ((HandlerState*)userData)->calls++;
    nc_coap_server_request_free(request);
}

// Confirmable POST /test with the given payload.
std::vector<uint8_t> post_packet(uint16_t messageId, size_t payloadSize)
{
    std::vector<uint8_t> packet = { 0x40, 0x02, (uint8_t)(messageId >> 8), (uint8_t)messageId, 0xB4, 't', 'e', 's', 't', 0xFF };
    packet.insert(packet.end(), payloadSize, 'x');
    return packet;
}

} // namespace

BOOST_AUTO_TEST_SUITE(coap_server_limits)

BOOST_AUTO_TEST_CASE(request_body_over_the_limit_is_rejected)
{
    auto tp = nabto::test::TestPlatform::create();
    struct nc_coap_server_context ctx;
    BOOST_REQUIRE(nc_coap_server_init(tp->getPlatform(), NULL, NULL, &ctx) == NABTO_EC_OK);
    // The events posted by the coap server must not run, they would send the
    // response to the fake connection below.
    tp->stop();

    HandlerState state;
    const char* path[] = { "test", NULL };
    struct nc_coap_server_resource* resource = NULL;
    BOOST_REQUIRE(nc_coap_server_add_resource(&ctx, NABTO_COAP_METHOD_POST, path, &count_handler, &state, &resource) == NABTO_COAP_ERROR_OK);

    nc_coap_server_limit_request_size(&ctx, 10);
    int connection = 0;

    std::vector<uint8_t> tooLarge = post_packet(1, 11);
    nabto_coap_server_handle_packet(&ctx.requests, &connection, tooLarge.data(), tooLarge.size());
    BOOST_TEST(state.calls == 0u);
    // The request is answered with an error response.
    BOOST_TEST(nabto_coap_server_next_event(&ctx.requests) == NABTO_COAP_SERVER_NEXT_EVENT_SEND);

    std::vector<uint8_t> atLimit = post_packet(2, 10);
    nabto_coap_server_handle_packet(&ctx.requests, &connection, atLimit.data(), atLimit.size());
    BOOST_TEST(state.calls == 1u);

    nabto_coap_server_remove_connection(&ctx.requests, &connection);
    nc_coap_server_remove_resource(resource);
    nc_coap_server_deinit(&ctx);
}

BOOST_AUTO_TEST_CASE(device_limit_coap_server_request_size)
{
    NabtoDevice* device = nabto_device_new();
    BOOST_REQUIRE(device != NULL);
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    // Unlimited by default.
    BOOST_TEST(dev->core.coapServer.requests.maxRequestPayload == SIZE_MAX);
    BOOST_TEST(nabto_device_limit_coap_server_request_size(device, 4096) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(dev->core.coapServer.requests.maxRequestPayload == 4096u);

    nabto_device_free(device);
}

BOOST_AUTO_TEST_SUITE_END()
