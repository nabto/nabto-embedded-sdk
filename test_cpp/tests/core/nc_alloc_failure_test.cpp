#include <boost/test/unit_test.hpp>

#include <test_platform.hpp>
#include <util/failing_allocator.hpp>

#include <core/nc_coap_server.h>

#include <vector>

BOOST_AUTO_TEST_SUITE(alloc_failure)

namespace {

struct HandlerState {
    size_t calls = 0;
};

void count_handler(struct nc_coap_server_request* request, void* userData)
{
    ((HandlerState*)userData)->calls++;
    nc_coap_server_request_free(request);
}

} // namespace

BOOST_AUTO_TEST_CASE(coap_server_request_allocation_failure_refuses_the_request)
{
    auto tp = nabto::test::TestPlatform::create();
    struct nc_coap_server_context ctx;
    BOOST_REQUIRE(nc_coap_server_init(tp->getPlatform(), NULL, NULL, &ctx) == NABTO_EC_OK);

    HandlerState state;
    const char* path[] = { "test", NULL };
    struct nc_coap_server_resource* resource = NULL;
    BOOST_REQUIRE(nc_coap_server_add_resource(&ctx, NABTO_COAP_METHOD_GET, path, &count_handler, &state, &resource) == NABTO_COAP_ERROR_OK);

    // Confirmable GET /test
    std::vector<uint8_t> packet = { 0x40, 0x01, 0x12, 0x34, 0xB4, 't', 'e', 's', 't' };
    int connection = 0;

    {
        nabto::test::FailingAllocator allocator;
        allocator.failSize(sizeof(struct nc_coap_server_request));
        // The packet is handed to the coap server directly, such that the
        // response is not sent to a connection.
        nabto_coap_server_handle_packet(&ctx.requests, &connection, packet.data(), packet.size());
        BOOST_TEST(allocator.failures() == 1u);
    }

    // The request is refused with an error response, not passed on to the
    // handler, and the server did not crash.
    BOOST_TEST(state.calls == 0u);
    BOOST_TEST(nabto_coap_server_next_event(&ctx.requests) == NABTO_COAP_SERVER_NEXT_EVENT_SEND);

    // Without the failure the same request reaches the handler.
    nabto_coap_server_remove_connection(&ctx.requests, &connection);
    nabto_coap_server_handle_packet(&ctx.requests, &connection, packet.data(), packet.size());
    BOOST_TEST(state.calls == 1u);

    nabto_coap_server_remove_connection(&ctx.requests, &connection);
    nc_coap_server_remove_resource(resource);
    nc_coap_server_deinit(&ctx);
}

BOOST_AUTO_TEST_SUITE_END()
