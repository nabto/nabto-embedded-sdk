#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string.hpp>

#include <util/io_service.hpp>
#include "coap_server.hpp"

BOOST_AUTO_TEST_SUITE(coap_server_fixture)

BOOST_AUTO_TEST_CASE(create, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto server = nabto::coap::CoapServer::create(ioService->getIoService());
}

BOOST_AUTO_TEST_CASE(add_resource, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto server = nabto::coap::CoapServer::create(ioService->getIoService());

    const char* echo[] = {"echo", NULL};
    struct nabto_coap_server_resource* r;
    server->addResource(NABTO_COAP_CODE_GET, echo, [](struct nabto_coap_server_request* request, void* userData){(void)request; (void)userData; }, NULL, &r );
}

BOOST_AUTO_TEST_SUITE_END()
