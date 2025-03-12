#include <boost/test/unit_test.hpp>

#include <core/nc_coap_server.h>
#include <core/nc_rendezvous.h>
#include <core/nc_rendezvous_coap.h>
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

        for (size_t i = 0; i < 16; i++) {
            cliConn.id.id[i] = i;
        }

        coapReq.connection = &cliConn;
        request.request = &coapReq;
        request.isVirtual = false;

        payload = nlohmann::json::to_cbor(jsonPay);
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

    std::cout << "EP: " << jsonPay.dump() << std::endl;

    auto ctx = nabto::test::RendezvousTestCtx(jsonPay);

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

    std::cout << "EP: " << jsonPay.dump() << std::endl;
    auto ctx = nabto::test::RendezvousTestCtx(jsonPay);

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

    std::cout << "EP: " << jsonPay.dump() << std::endl;
    auto ctx = nabto::test::RendezvousTestCtx(jsonPay);

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

    std::cout << "EP: " << jsonPay.dump() << std::endl;
    auto ctx = nabto::test::RendezvousTestCtx(jsonPay);

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

    std::cout << "EP: " << jsonPay.dump() << std::endl;
    auto ctx = nabto::test::RendezvousTestCtx(jsonPay);

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

    std::cout << "EP: " << jsonPay.dump() << std::endl;
    auto ctx = nabto::test::RendezvousTestCtx(jsonPay);

    bool ret = handle_rendezvous_payload(&ctx.ctx, &ctx.request, ctx.payload.data(), ctx.payload.size());
    BOOST_TEST(!ret);

}

BOOST_AUTO_TEST_CASE(rendezvous_payload_invalid3, *boost::unit_test::timeout(300))
{
    nlohmann::json jsonPay = nlohmann::json::array();

    nlohmann::json jsonEp;

    jsonPay.push_back(jsonEp);

    std::cout << "EP: " << jsonPay.dump() << std::endl;
    auto ctx = nabto::test::RendezvousTestCtx(jsonPay);

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

    std::cout << "EP: " << jsonPay.dump() << std::endl;
    auto ctx = nabto::test::RendezvousTestCtx(jsonPay);

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

    std::cout << "EP: " << jsonPay.dump() << std::endl;
    auto ctx = nabto::test::RendezvousTestCtx(jsonPay);

    auto pl = ctx.payload;
    auto it = pl.end();
    it--;
    pl.erase(it);

    bool ret = handle_rendezvous_payload(&ctx.ctx, &ctx.request, pl.data(), pl.size());
    BOOST_TEST(!ret);

}

BOOST_AUTO_TEST_SUITE_END()
