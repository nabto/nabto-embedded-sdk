#include <boost/test/unit_test.hpp>

#include <core/nc_client_connection.h>
#include <core/nc_client_connection_dispatch.h>
#include <core/nc_coap_server.h>
#include <core/nc_protocol_defines.h>
#include <core/nc_rendezvous.h>
#include <core/nc_rendezvous_coap.h>
#include <core/nc_udp_dispatch.h>
#include <test_platform.hpp>
#include <coap/src/nabto_coap_server_impl.h>

#include <nlohmann/json.hpp>

extern "C" {
bool handle_rendezvous_payload(struct nc_rendezvous_coap_context* ctx, struct nc_coap_server_request* request, uint8_t* payload, size_t payloadLength);
}

namespace nabto {
namespace test {

class RendezvousTestCtx {
public:
    std::unique_ptr<nabto::test::TestPlatform> tp;
    struct nc_rendezvous_context rendezvous;
    struct nc_rendezvous_coap_context ctx;
    struct nc_client_connection cliConn;
    struct nabto_coap_server_request coapReq;
    struct nc_coap_server_request request;
    std::vector<uint8_t> payload;

    RendezvousTestCtx(nlohmann::json jsonPay) {
        tp = nabto::test::TestPlatform::create();

        nc_rendezvous_init(&rendezvous, tp->getPlatform());
        ctx.rendezvous = &rendezvous;

        for (uint8_t i = 0; i < 16; i++) {
            cliConn.id.id[i] = i;
        }

        coapReq.connection = &cliConn;
        request.request = &coapReq;
        request.isVirtual = false;

        payload = nlohmann::json::to_cbor(jsonPay);
    }

    ~RendezvousTestCtx() {
        nc_rendezvous_deinit(&rendezvous);
    }
};

class RendezvousPacketTestCtx {
public:
    std::unique_ptr<nabto::test::TestPlatform> tp;
    struct nc_rendezvous_context rendezvous;
    struct nc_connections_context connections = {};
    struct nc_client_connection_dispatch_context dispatch = {};
    struct nc_connection connection = {};
    struct nc_client_connection cliConn = {};
    struct nc_udp_dispatch_context udp = {};
    struct np_udp_endpoint ep = {};

    RendezvousPacketTestCtx() {
        tp = nabto::test::TestPlatform::create();
        struct np_platform* pl = tp->getPlatform();

        nc_rendezvous_init(&rendezvous, pl);
        // Pretend a send is in flight such that responses stay in the queue
        // where the test can inspect them instead of being sent.
        rendezvous.sendBuffer = pl->buf.allocate();

        // connection id is prefix byte, 14 id bytes and a channel id
        cliConn.id.id[0] = NABTO_PROTOCOL_PREFIX_CONNECTION;
        for (uint8_t i = 1; i < 15; i++) {
            cliConn.id.id[i] = i;
        }
        cliConn.id.id[15] = 42;

        connection.isVirtual = false;
        connection.connectionImplCtx = &cliConn;
        nn_llist_init(&connections.connections);
        nn_llist_append(&connections.connections, &connection.connectionsNode, &connection);
        dispatch.connections = &connections;
    }

    ~RendezvousPacketTestCtx() {
        nn_llist_erase_node(&connection.connectionsNode);
        nc_rendezvous_deinit(&rendezvous);
    }

    std::vector<uint8_t> clientRequest(uint8_t channelId) {
        std::vector<uint8_t> packet;
        packet.push_back(NABTO_PROTOCOL_PREFIX_RENDEZVOUS);
        packet.insert(packet.end(), cliConn.id.id + 1, cliConn.id.id + 15);
        packet.push_back(channelId);
        packet.push_back(CT_RENDEZVOUS_CLIENT_REQUEST);
        return packet;
    }

    void handlePacket(std::vector<uint8_t>& packet) {
        // udp is only used when sending, which is blocked by the in flight sendBuffer.
        nc_rendezvous_handle_packet(&rendezvous, &udp, &dispatch, &ep, packet.data(), (uint16_t)packet.size());
    }
};

} } // namespaces

BOOST_AUTO_TEST_SUITE(rendezvous)

BOOST_AUTO_TEST_CASE(rendezvous_payload_v4, *boost::unit_test::timeout(300))
{
    nlohmann::json jsonPay = nlohmann::json::array();

    nlohmann::json jsonEp;
    std::vector<uint8_t> ip = { 127,0,0,1 };
    jsonEp["Ip"] = nlohmann::json::binary(ip);
    jsonEp["Port"] = 4444;
    jsonPay.push_back(jsonEp);


    nabto::test::RendezvousTestCtx ctx(jsonPay);

    bool ret = handle_rendezvous_payload(&ctx.ctx, &ctx.request, ctx.payload.data(), ctx.payload.size());
    BOOST_TEST(ret);
}


BOOST_AUTO_TEST_CASE(rendezvous_payload_v6, *boost::unit_test::timeout(300))
{
    nlohmann::json jsonPay = nlohmann::json::array();

    nlohmann::json jsonEp;
    std::vector<uint8_t> ip = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
    jsonEp["Ip"] = nlohmann::json::binary(ip);
    jsonEp["Port"] = 4444;
    jsonPay.push_back(jsonEp);

    nabto::test::RendezvousTestCtx ctx(jsonPay);

    bool ret = handle_rendezvous_payload(&ctx.ctx, &ctx.request, ctx.payload.data(), ctx.payload.size());
    BOOST_TEST(ret);
}

BOOST_AUTO_TEST_CASE(rendezvous_payload_combi, *boost::unit_test::timeout(300))
{
    nlohmann::json jsonPay = nlohmann::json::array();

    {
        nlohmann::json jsonEp;
        std::vector<uint8_t> ip = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
        jsonEp["Ip"] = nlohmann::json::binary(ip);
        jsonEp["Port"] = 4444;
        jsonPay.push_back(jsonEp);
    }

    {
        nlohmann::json jsonEp;
        std::vector<uint8_t> ip = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
        jsonEp["Ip"] = nlohmann::json::binary(ip);
        jsonEp["Port"] = 4444;
        jsonPay.push_back(jsonEp);
    }

    nabto::test::RendezvousTestCtx ctx(jsonPay);

    bool ret = handle_rendezvous_payload(&ctx.ctx, &ctx.request, ctx.payload.data(), ctx.payload.size());
    BOOST_TEST(ret);

}

BOOST_AUTO_TEST_CASE(rendezvous_payload_v4_mapped, *boost::unit_test::timeout(300))
{
    nlohmann::json jsonPay = nlohmann::json::array();

    nlohmann::json jsonEp;
    std::vector<uint8_t> ip = { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,127,0,0,1 };
    jsonEp["Ip"] = nlohmann::json::binary(ip);
    jsonEp["Port"] = 4444;
    jsonPay.push_back(jsonEp);

    nabto::test::RendezvousTestCtx ctx(jsonPay);

    bool ret = handle_rendezvous_payload(&ctx.ctx, &ctx.request, ctx.payload.data(), ctx.payload.size());
    BOOST_TEST(ret);

}

BOOST_AUTO_TEST_CASE(rendezvous_payload_invalid, *boost::unit_test::timeout(300))
{
    nlohmann::json jsonPay = nlohmann::json::array();

    nlohmann::json jsonEp;
    std::vector<uint8_t> ip = { 0xFF,0xFF,127,0,0,1 };
    jsonEp["Ip"] = nlohmann::json::binary(ip);
    jsonEp["Port"] = 0;
    jsonPay.push_back(jsonEp);

    nabto::test::RendezvousTestCtx ctx(jsonPay);

    bool ret = handle_rendezvous_payload(&ctx.ctx, &ctx.request, ctx.payload.data(), ctx.payload.size());
    BOOST_TEST(ret);

}

BOOST_AUTO_TEST_CASE(rendezvous_payload_invalid2, *boost::unit_test::timeout(300))
{
    nlohmann::json jsonPay = nlohmann::json::array();
    nlohmann::json jsonArr = nlohmann::json::array();

    nlohmann::json jsonEp;
    std::vector<uint8_t> ip;
    jsonEp["Ip"] = nlohmann::json::binary(ip);
    jsonEp["Port"] = 0;
    jsonArr.push_back(jsonEp);

    jsonPay.push_back(jsonArr);

    nabto::test::RendezvousTestCtx ctx(jsonPay);

    bool ret = handle_rendezvous_payload(&ctx.ctx, &ctx.request, ctx.payload.data(), ctx.payload.size());
    BOOST_TEST(!ret);

}

BOOST_AUTO_TEST_CASE(rendezvous_payload_invalid3, *boost::unit_test::timeout(300))
{
    nlohmann::json jsonPay = nlohmann::json::array();

    nlohmann::json jsonEp;

    jsonPay.push_back(jsonEp);

    nabto::test::RendezvousTestCtx ctx(jsonPay);

    bool ret = handle_rendezvous_payload(&ctx.ctx, &ctx.request, ctx.payload.data(), ctx.payload.size());
    BOOST_TEST(!ret);

}

BOOST_AUTO_TEST_CASE(rendezvous_payload_invalid4, *boost::unit_test::timeout(300))
{
    nlohmann::json jsonPay = nlohmann::json::array();

    nlohmann::json jsonEp;
    jsonEp["Ip"] = "not really IP";
    jsonEp["Port"] = "4242";

    jsonPay.push_back(jsonEp);
    jsonPay.push_back(jsonEp);

    nabto::test::RendezvousTestCtx ctx(jsonPay);

    bool ret = handle_rendezvous_payload(&ctx.ctx, &ctx.request, ctx.payload.data(), ctx.payload.size());
    BOOST_TEST(!ret); // Invalid endpoints are ignored so we expect true

}


BOOST_AUTO_TEST_CASE(rendezvous_payload_invalid5, *boost::unit_test::timeout(300))
{
    nlohmann::json jsonPay = nlohmann::json::array();

    nlohmann::json jsonEp;
    std::vector<uint8_t> ip = { 0xFF,0xFF,127,0,0,1 };
    jsonEp["Ip"] = nlohmann::json::binary(ip);
    jsonEp["Port"] = 0;
    jsonPay.push_back(jsonEp);

    nabto::test::RendezvousTestCtx ctx(jsonPay);

    auto pl = ctx.payload;
    auto it = pl.end();
    it--;
    pl.erase(it);

    bool ret = handle_rendezvous_payload(&ctx.ctx, &ctx.request, pl.data(), pl.size());
    BOOST_TEST(!ret);

}

BOOST_AUTO_TEST_CASE(rendezvous_client_request_known_connection, *boost::unit_test::timeout(300))
{
    nabto::test::RendezvousPacketTestCtx ctx;

    // Use a channel id different from the one the connection was created
    // with, the channel id must not be part of the connection id match.
    std::vector<uint8_t> packet = ctx.clientRequest(7);
    ctx.handlePacket(packet);

    BOOST_TEST(ctx.rendezvous.packetIndex == 1);
    struct nc_rendezvous_send_packet* response = &ctx.rendezvous.packetList[0];
    BOOST_TEST(response->type == CT_RENDEZVOUS_CLIENT_RESPONSE);
    BOOST_TEST(memcmp(response->connectionId, ctx.cliConn.id.id + 1, 14) == 0);
    BOOST_TEST(response->channelId == 7);
}

BOOST_AUTO_TEST_CASE(rendezvous_client_request_unknown_connection, *boost::unit_test::timeout(300))
{
    nabto::test::RendezvousPacketTestCtx ctx;

    std::vector<uint8_t> packet = ctx.clientRequest(7);
    packet[1] ^= 0xFF;
    ctx.handlePacket(packet);

    BOOST_TEST(ctx.rendezvous.packetIndex == 0);
}

BOOST_AUTO_TEST_SUITE_END()
